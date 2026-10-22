#!/usr/bin/env python3
"""Differential AOT validation of synthetic bounded memory and forward branches."""
import argparse
import hashlib
import json
import platform
import random
import subprocess
from pathlib import Path

from memory_lift import MEMORY_BYTES, lift_memory

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-memory')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('run with native ARM64 Python on Apple Silicon')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'synthetic bounded memory and forward branches',
              'game_execution': False, 'commands': []}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    def run(label, argv, inputs=None):
        result = subprocess.run([str(arg) for arg in argv], capture_output=True, text=True,
                                input=inputs, timeout=60)
        (out / f'{label}.stdout.txt').write_text(result.stdout)
        (out / f'{label}.stderr.txt').write_text(result.stderr)
        report['commands'].append({'argv': [str(arg) for arg in argv], 'exit_code': result.returncode})
        if result.returncode:
            raise RuntimeError(f'{label}: exit {result.returncode}; see {out}')
        return result.stdout

    save()
    try:
        fixtures = json.loads((ROOT / 'memory_fixtures.json').read_text())
        if not isinstance(fixtures, dict) or not fixtures:
            raise ValueError('expected a non-empty fixture map')
        codes = {name: bytes.fromhex(code) for name, code in fixtures.items()}
        (out / 'memory.ll').write_text('\n\n'.join(lift_memory(code, name) for name, code in codes.items()) + '\n')
        assembly = ['.text']
        for name, code in codes.items():
            assembly.extend([f'.globl _{name}', f'_{name}:',
                             '.byte ' + ','.join(str(byte) for byte in code)])
        (out / 'original.s').write_text('\n'.join(assembly) + '\n')
        harness = '''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
DECLARATIONS
int main(void) {
    uint64_t a, b;
    uint64_t (*functions[])(unsigned char *, uint64_t) = {FUNCTIONS};
    while (scanf("%" SCNx64 " %" SCNx64, &a, &b) == 2) {
        for (unsigned f = 0; f < sizeof(functions)/sizeof(functions[0]); ++f) {
            _Alignas(16) unsigned char bytes[96], before[96];
            for (unsigned i = 0; i < sizeof(bytes); ++i)
                bytes[i] = (unsigned char)((a >> (8 * (i % 8))) ^
                    (b >> (8 * ((i + 3) % 8))) ^ (i * 37));
            for (unsigned i = 0; i < 8; ++i) bytes[16 + i] = (unsigned char)(a >> (8 * i));
            memcpy(before, bytes, sizeof(bytes));
            uint64_t result = functions[f](bytes + 16, b);
            if (memcmp(before, bytes, 16) || memcmp(before + 80, bytes + 80, 16)) {
                fprintf(stderr, "guard corruption in fixture %u\\n", f);
                return 3;
            }
            printf("%016" PRIx64 ":", result);
            for (unsigned i = 0; i < sizeof(bytes); ++i) printf("%02x", bytes[i]);
            putchar('\\n');
        }
    }
    return ferror(stdin) || ferror(stdout);
}
'''.replace('DECLARATIONS', '\n'.join(
            f'extern uint64_t {name}(unsigned char *, uint64_t);' for name in codes)
        ).replace('FUNCTIONS', ','.join(codes))
        (out / 'harness.c').write_text(harness)
        edge = [0, 1, 2, 31, 32, 63, 64, 127, 128, 255, 256, 32767, 32768,
                65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
                (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        pairs = [(a, b) for a in edge for b in edge]
        rng = random.Random(0xbb109)
        pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(1024))
        inputs = ''.join(f'{a:016x} {b:016x}\n' for a, b in pairs)
        (out / 'inputs.txt').write_text(inputs)
        outputs = {}
        for label, arch, source in [('original-x86_64', 'x86_64', 'original.s'),
                                    ('aot-x86_64', 'x86_64', 'memory.ll'),
                                    ('aot-arm64', 'arm64', 'memory.ll')]:
            exe = out / label
            run(f'build-{label}', ['xcrun', 'clang', '-arch', arch, '-O2',
                                 out / 'harness.c', out / source, '-o', exe])
            outputs[label] = run(label, ['/usr/bin/arch', f'-{arch}', exe], inputs).splitlines()
        reference = outputs['original-x86_64']
        comparisons = len(pairs) * len(codes)
        if len(reference) != comparisons:
            raise RuntimeError('incomplete reference output')
        for label, rows in outputs.items():
            if rows != reference:
                first = next((i for i, (a, b) in enumerate(zip(reference, rows)) if a != b),
                             min(len(reference), len(rows)))
                report['mismatch'] = {'backend': label, 'row': first}
                if first < comparisons:
                    report['mismatch'].update(fixture=list(codes)[first % len(codes)],
                                              inputs=[hex(value) for value in pairs[first // len(codes)]])
                raise RuntimeError(f'{label}: mismatch at row {first}')
        report.update(status='passed', host=platform.platform(), machine=platform.machine(),
                      compiler=run('compiler', ['xcrun', 'clang', '--version']),
                      seed='0xbb109', fixtures=len(codes), input_pairs=len(pairs),
                      comparisons_per_aot_backend=comparisons, mismatches=0,
                      observed_outputs=['RAX', f'{MEMORY_BYTES}-byte region', 'two 16-byte guards'],
                      oracle='original x86 bytes under Rosetta; development reference only',
                      source_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                     for path in (ROOT / 'memory_lift.py', ROOT / 'memory_fixtures.json',
                                                  ROOT / 'run_memory.py')},
                      inputs_sha256=hashlib.sha256(inputs.encode()).hexdigest())
        print(f'PASS: {comparisons} return/memory comparisons per AOT backend, 0 mismatches')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(f'FAIL: {error}')
    save()
    print(report_path)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
