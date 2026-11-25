#!/usr/bin/env python3
"""Build the native ARM64 loader and run it on the standard linked PS4 image."""
import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from run_real_nonleaf import ROOT, MODULE_SHA, selection
from state_stack_lift import CODE_BASE, lift

TOP = ROOT.parent
LIMIT = 512 * 1024 * 1024
RETURN = CODE_BASE + LIMIT


def run(game, out):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ValueError('use native Python on Apple Silicon')
    code, plt, name, call_pc, offsets = selection(game / 'sce_module/libSceFios2.prx')
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        folder = Path(tmp)
        for script in ('prepare.py', 'link_modules.py'):
            subprocess.run([sys.executable, TOP / 'scripts' / script, game, '--out', folder],
                           check=True, timeout=120)
        modules = json.loads((folder / 'link.json').read_text())['modules']
        if len(modules) != 2 or modules[1]['sha256'] != MODULE_SHA:
            raise ValueError('unexpected linked module layout')
        base = int(modules[1]['base'], 16)
        target = base + offsets['PLT_OFFSET']
        entry = base + offsets['FUNCTION_OFFSET']
        spec = {
            'fios_cond': {'address': entry, 'parts': [code.hex()], 'host_imports': {str(call_pc): target}},
            'tls_self': {'address': LIMIT - 0x1000, 'parts': ['65488b042500000000c3']},
        }
        ir, *_ = lift(spec, mapped=True, real=True, image_limit=LIMIT, root_return=RETURN, region_limit=LIMIT)
        (folder / 'fios.ll').write_text(ir)
        constants = dict(AOT_BASE=CODE_BASE, AOT_RETURN=RETURN, AOT_MODULE_BASE=base,
                         AOT_OFFSET=entry, AOT_PLT=target, AOT_GOT=base + offsets['GOT_OFFSET'])
        header = [f'#define {key} UINT64_C({value})' for key, value in constants.items()]
        header += ['#define AOT_COND_NAME "2Tb92quprl0#p#J"',
                   'extern void entry_fios_cond(BbCpuState *, BbGuestRegions *, BbGuestMemory *);',
                   'extern void entry_tls_self(BbCpuState *, BbGuestRegions *, BbGuestMemory *);']
        for label, data in (('body', code), ('plt', plt), ('name', name)):
            header.append(f'static const unsigned char aot_{label}[] = {{' + ', '.join(map(str, data)) + '};')
        (folder / 'aot_entries.h').write_text('\n'.join(header) + '\n')
        subprocess.run(['clang', '-arch', 'arm64', '-O2', '-Wno-override-module',
                        '-c', folder / 'fios.ll', '-o', folder / 'fios.o'], check=True, timeout=60)
        binary = folder / 'bb-probe-aot'
        subprocess.run(['clang', '-arch', 'arm64', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-Wno-ignored-attributes', '-DBB_LOW_HEAP_IMPL', '-I', TOP / 'src',
                        '-I', ROOT, '-I', folder, TOP / 'src/aot_loader.c', TOP / 'src/boot_image.c',
                        ROOT / 'state_regions.c', TOP / 'src/runtime_mutex.c', folder / 'fios.o',
                        '-o', binary], check=True, timeout=60)
        arch = subprocess.check_output(['lipo', '-archs', binary], text=True, timeout=60).strip()
        if arch != 'arm64':
            raise ValueError('loader is not a thin ARM64 executable')
        result = subprocess.run([binary, folder / 'boot-linked.bin'], check=True,
                                capture_output=True, text=True, timeout=60)
        (out / 'loader.log').write_text(result.stdout)
        print(result.stdout, end='')
        for name in ('bb-probe-aot', 'boot-linked.bin'):
            (folder / name).replace(out / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=TOP / 'out/cpu-aot-loader')
    args = parser.parse_args()
    try:
        run(args.game_dir.resolve(), args.out.resolve())
    except subprocess.CalledProcessError as error:
        parser.exit(1, f'{error}\n{error.stdout or ""}{error.stderr or ""}')
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
