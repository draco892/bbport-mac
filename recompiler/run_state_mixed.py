#!/usr/bin/env python3
"""Run mixed guest-state execution and concurrent atomics checks on Apple Silicon."""
import argparse
import json
import platform
import subprocess
from pathlib import Path

from cpu_state import c_layout_checks
from run_simd import VENDOR, sha
from state_stack_lift import lift

ROOT = Path(__file__).resolve().parent
FIXTURES = {
    # MOVDQU xmm8,[rdi]; PADDB xmm8,xmm9; MOVDQU [rsi],xmm8.
    'vector': ['f3440f6f0766450ffcc1f3440f7f06c3'],
    'aligned': ['66440f6f07c3'],
    'exchange': ['4887070faef0c3'],
    'trap': ['48ffc00f0b48ffc0c3'],
    'partial': ['4500c8664501c8c3'],
    'nested_trap': [{'call': 'trap'}, 'c3'],
    'scalar_copy': ['488b07488906c3'],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-state-mixed')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('use native ARM64 Python on Apple Silicon')

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'runs': {}}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    def run(label, args):
        command = [str(arg) for arg in args]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        report['runs'][label] = {'command': command, 'exit_code': result.returncode}
        (out / f'{label}.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f'{label} failed. See {out / (label + ".log")}')
        if result.stdout:
            print(result.stdout.strip(), flush=True)

    save()
    try:
        manifest = json.loads((VENDOR / 'manifest.json').read_text())
        for name, digest in manifest['files_sha256'].items():
            if sha(VENDOR / name) != digest:
                raise ValueError(f'SoftFloat hash mismatch for {name}')
        fixtures = {name: {'address': i * 256, 'parts': parts}
                    for i, (name, parts) in enumerate(FIXTURES.items())}
        ir, *_ = lift(fixtures, mapped=True)
        (out / 'mixed.ll').write_text(ir)
        (out / 'fixtures.json').write_text(json.dumps(fixtures, indent=2) + '\n')
        (out / 'cpu_state_layout.h').write_text(c_layout_checks())
        options = ['-DSOFTFLOAT_FAST_INT64', '-DINLINE_LEVEL=5', '-DSOFTFLOAT_FAST_DIV32TO16',
                   '-DSOFTFLOAT_FAST_DIV64TO32', '-DTHREAD_LOCAL=_Thread_local']
        includes = [VENDOR / 'build/Linux-x86_64-GCC', VENDOR / 'source/8086-SSE',
                    VENDOR / 'source/include', ROOT, out]
        sources = [ROOT / 'state_mixed_harness.c', ROOT / 'state_regions.c',
                   ROOT / 'simd_fp.c', out / 'mixed.ll', *(VENDOR / n for n in manifest['sources'])]
        builds = [('aot-x86', 'x86_64', []), ('aot-arm', 'arm64', [])]
        if args.sanitize:
            builds.append(('aot-arm-ubsan', 'arm64', ['-fsanitize=undefined', '-fno-sanitize-recover=all']))
        for label, arch, sanitizer in builds:
            exe = out / label
            run(label + '-build', ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2',
                                  '-Wall', '-Wextra', '-pthread', *options, *sanitizer,
                                  *(arg for path in includes for arg in ['-I', path]),
                                  *sources, '-o', exe])
            run(label + '-run', ['/usr/bin/arch', '-' + arch, exe])
        report.update(status='passed', concurrent_exchanges_per_backend=4096,
                      threads=4, native_ubsan=args.sanitize)
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
