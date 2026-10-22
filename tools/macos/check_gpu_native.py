#!/usr/bin/env python3
"""Check native GPU build/loading, IPC and Vulkan readback without game files."""
import argparse
import datetime
import json
import os
import platform
import subprocess
from pathlib import Path

from cpu_baseline import ROOT, file_info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deps', type=Path,
                        default=Path(os.environ.get('BB_DEPS_ARM64', ROOT / 'deps-arm64')))
    parser.add_argument('--gpu', type=Path,
                        default=Path(os.environ.get('BB_GPU_PROCESS', ROOT / 'out/gpu-arm64/bb-gpu')))
    parser.add_argument('--out', type=Path)
    parser.add_argument('--skip-rosetta', action='store_true',
                        help='run only native checks; omit the x86-to-ARM64 reference test')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('run with native ARM64 Python on Apple Silicon')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = (args.out or ROOT / 'out/native-gpu-check' / stamp).resolve()
    if out.exists():
        parser.error(f'output directory already exists: {out}')
    out.mkdir(parents=True)
    deps, gpu = args.deps.resolve(), args.gpu.resolve()
    report = {'status': 'incomplete', 'scope': 'no-game native GPU prerequisites only',
              'gameplay_tested': False, 'rosetta_reference_included': not args.skip_rosetta,
              'steps': [], 'artifacts': {}}
    report_path = out / 'verification.json'

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    def step(name, argv, expected=0, marker=None, env=None):
        argv = [str(item) for item in argv]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                timeout=60, env=env)
        output = result.stdout + result.stderr
        (out / f'{name}.log').write_text(output)
        passed = result.returncode == expected and (marker is None or marker in output)
        report['steps'].append({'name': name, 'command': argv, 'exit_code': result.returncode,
                                'expected_exit_code': expected, 'required_output': marker,
                                'passed': passed})
        save()
        if not passed:
            raise RuntimeError(f'{name}: unexpected result; see {out / (name + ".log")}')
        print(f'PASS: {name}', flush=True)
        return output

    save()
    try:
        artifacts = {'gpu': gpu, 'gpu_library': gpu.parent / 'libbbgpu.dylib',
                     'driver': deps / 'lib/kosmickrisp/libvulkan_kosmickrisp.dylib',
                     'vulkan_loader': deps / 'lib/libvulkan.1.dylib'}
        for name, path in artifacts.items():
            info = file_info(path, binary=True)
            report['artifacts'][name] = info
            if 'arm64' not in info.get('architectures', {}).get('stdout', '').split():
                raise RuntimeError(f'{name}: missing ARM64 artifact {path}')
        report['compiler'] = step('compiler', ['xcrun', 'clang', '--version'])
        for name, source, archs in [
            ('channel', 'test_remote_channel.cpp', ['arm64']),
            ('memory', 'test_remote_memory.cpp', ['arm64'] if args.skip_rosetta else ['x86_64', 'arm64']),
            ('table-cache', 'test_remote_table_cache.cpp', ['arm64']),
        ]:
            flags = [arg for arch in archs for arg in ('-arch', arch)]
            step(f'build-{name}', ['xcrun', 'clang++', '-std=c++20', '-O2', '-pthread',
                                   *flags, '-I', ROOT / 'gpu/shim', ROOT / 'tests' / source,
                                   '-o', out / name])
        step('channel-arm64', ['/usr/bin/arch', '-arm64', out / 'channel'],
             marker='200000 messages in order, 16000 calls')
        step('memory-arm64', ['/usr/bin/arch', '-arm64', out / 'memory'],
             marker='game side arm64')
        if not args.skip_rosetta:
            step('memory-rosetta-arm64', ['/usr/bin/arch', '-x86_64', out / 'memory'],
                 marker='game side x86-64 under Rosetta')
        step('table-cache-arm64', ['/usr/bin/arch', '-arm64', out / 'table-cache'],
             marker='vma table cache: PASS')
        env = os.environ.copy()
        env['DYLD_LIBRARY_PATH'] = str(deps / 'lib')
        env['VK_DRIVER_FILES'] = str(deps / 'lib/kosmickrisp/kosmickrisp_mesa_icd.json')
        env.pop('VK_ICD_FILENAMES', None)
        # Resolve lazy imports too, before the expected no-arguments diagnostic.
        env['DYLD_BIND_AT_LAUNCH'] = '1'
        step('gpu-load', [gpu], expected=2,
             marker='bb-gpu: the game process starts this (BB_NATIVE_GPU=1)', env=env)
        (out / 'smoke_main.c').write_text('int vulkan_smoke(void);\nint main(void) { return vulkan_smoke(); }\n')
        step('build-vulkan-smoke', ['xcrun', 'clang', '-arch', 'arm64', '-std=c11', '-O2',
                                  '-I', deps / 'include', ROOT / 'src/vulkan_smoke.c',
                                  out / 'smoke_main.c', '-L', deps / 'lib', '-lvulkan',
                                  f'-Wl,-rpath,{deps / "lib"}', '-o', out / 'vulkan-smoke'])
        step('vulkan-readback-arm64', [out / 'vulkan-smoke'],
             marker='command submission + 4096-byte readback PASS', env=env)
        report['runtime_environment'] = {key: env[key] for key in
                                         ('DYLD_LIBRARY_PATH', 'VK_DRIVER_FILES', 'DYLD_BIND_AT_LAUNCH')}
        report['status'] = 'passed'
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        print(f'FAIL: {error}', flush=True)
    save()
    print(report_path)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
