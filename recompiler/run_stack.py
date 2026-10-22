#!/usr/bin/env python3
"""Compare real x86 stacks/direct calls with explicit-state LLVM AOT on ARM64."""
import argparse
import hashlib
import json
import platform
import random
import subprocess
from pathlib import Path

from stack_lift import ROOT_RETURN, STACK_BYTES, assemble, lift_stack

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-stack')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('run with native ARM64 Python on Apple Silicon')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'synthetic stack and statically resolved direct calls',
              'game_execution': False, 'commands': []}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    def run(label, argv, inputs=None):
        argv = [str(arg) for arg in argv]
        result = subprocess.run(argv, capture_output=True, text=True, input=inputs, timeout=60)
        (out / f'{label}.stdout.txt').write_text(result.stdout)
        (out / f'{label}.stderr.txt').write_text(result.stderr)
        report['commands'].append({'argv': argv, 'exit_code': result.returncode})
        if result.returncode:
            raise RuntimeError(f'{label}: exit {result.returncode}; see {out}')
        return result.stdout

    save()
    try:
        functions = assemble(json.loads((ROOT / 'stack_fixtures.json').read_text()))
        ir, analyses = lift_stack(functions)
        (out / 'stack.ll').write_text(ir + '\n')
        (out / 'module.json').write_text(json.dumps({name: {'address': f['address'], 'code': f['code'].hex()}
                                                    for name, f in functions.items()}, indent=2) + '\n')
        assembly = ['.text', '.globl _stack_image', '_stack_image:']
        end = 0
        for name, function in sorted(functions.items(), key=lambda item: item[1]['address']):
            address, code = function['address'], function['code']
            if address > end:
                assembly.append(f'.space {address - end}, 0')
            assembly.extend([f'.globl _original_{name}', f'_original_{name}:',
                             '.byte ' + ','.join(str(byte) for byte in code)])
            end = address + len(code)
        (out / 'original.s').write_text('\n'.join(assembly) + '\n')
        header = ['#ifdef ORIGINAL']
        header.extend(f'extern void original_{name}(void);' for name in functions)
        header.append('static void (*entries[])(void) = {' + ','.join(f'original_{name}' for name in functions) + '};')
        header.append('#else')
        header.extend(f'extern void translated_{name}(Cpu *, unsigned char *, unsigned char *, uint64_t);'
                      for name in functions)
        header.append('static void (*entries[])(Cpu *, unsigned char *, unsigned char *, uint64_t) = {'
                      + ','.join(f'translated_{name}' for name in functions) + '};')
        header.append('#endif')
        (out / 'entries.h').write_text('\n'.join(header) + '\n')
        # Keep C and LLVM model constants synchronized explicitly.
        harness = (ROOT / 'stack_harness.c').read_text()
        if f'#define STACK_BYTES {STACK_BYTES}' not in harness or hex(ROOT_RETURN) not in harness:
            raise ValueError('harness and translator stack constants differ')
        (out / 'harness.c').write_text(harness)
        (out / 'bridge.s').write_text((ROOT / 'stack_bridge.s').read_text())
        edge = [0, 1, 2, 31, 32, 63, 64, 127, 128, 255, 256, 32767, 32768,
                65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
                (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        pairs = [(a, b) for a in edge for b in edge]
        rng = random.Random(0xbb109)
        pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(1024))
        inputs = ''.join(f'{a:016x} {b:016x}\n' for a, b in pairs)
        (out / 'inputs.txt').write_text(inputs)
        outputs = {}
        for label, arch in [('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')]:
            original = label == 'original-x86_64'
            sources = [out / 'original.s', out / 'bridge.s'] if original else [out / 'stack.ll']
            exe = out / label
            run(f'build-{label}', ['xcrun', 'clang', '-arch', arch, '-O2',
                                 '-DORIGINAL' if original else '-DTRANSLATED',
                                 out / 'harness.c', *sources, '-o', exe])
            outputs[label] = run(label, ['/usr/bin/arch', f'-{arch}', exe], inputs).splitlines()
        reference = outputs['original-x86_64']
        comparisons = len(pairs) * len(functions)
        if len(reference) != comparisons:
            raise RuntimeError('incomplete original output')
        for label, rows in outputs.items():
            if rows != reference:
                first = next((i for i, (a, b) in enumerate(zip(reference, rows)) if a != b),
                             min(len(reference), len(rows)))
                report['mismatch'] = {'backend': label, 'row': first}
                if first < comparisons:
                    report['mismatch'].update(function=list(functions)[first % len(functions)],
                                              inputs=[hex(v) for v in pairs[first // len(functions)]])
                raise RuntimeError(f'{label}: mismatch at row {first}')
        report.update(status='passed', host=platform.platform(), machine=platform.machine(),
                      compiler=run('compiler', ['xcrun', 'clang', '--version']),
                      seed='0xbb109', functions=len(functions), input_pairs=len(pairs),
                      comparisons_per_aot_backend=comparisons, mismatches=0,
                      required_stack_by_function={name: a['required_stack'] for name, a in analyses.items()},
                      observed_outputs=['RAX', 'RSI', 'RBX', 'RBP', 'normalized RSP delta',
                                        '64-byte memory region and two 16-byte guards'],
                      translated_stack_guards='two 16-byte guards; checked independently',
                      oracle='original x86 CALL/RET on host stack under Rosetta',
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in ('stack_lift.py', 'memory_lift.py', 'stack_fixtures.json',
                                                  'stack_harness.c', 'stack_bridge.s', 'run_stack.py')},
                      inputs_sha256=hashlib.sha256(inputs.encode()).hexdigest())
        print(f'PASS: {comparisons} register/memory/stack-balance comparisons per AOT backend, 0 mismatches')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(f'FAIL: {error}')
    save()
    print(report_path)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
