#!/usr/bin/env python3
"""Validate guest code-address resolution and bounded indirect calls on Apple ARM64."""
import argparse
import hashlib
import json
import platform
import random
import subprocess
from pathlib import Path

from indirect_lift import CODE_BASE, lift_indirect
from stack_lift import ROOT_RETURN, STACK_BYTES

ROOT = Path(__file__).resolve().parent
LEAVES = ('leaf_add', 'leaf_sub', 'leaf_transform')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-indirect')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('run with native ARM64 Python on Apple Silicon')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'synthetic guest code registry and bounded indirect calls',
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
        ir, analyses, functions, targets = lift_indirect(json.loads((ROOT / 'indirect_fixtures.json').read_text()))
        (out / 'indirect.ll').write_text(ir + '\n')
        module = {name: {'offset': f['address'], 'guest_address': CODE_BASE + f['address'], 'code': f['code'].hex()}
                  for name, f in functions.items()}
        (out / 'module.json').write_text(json.dumps(module, indent=2) + '\n')
        sites = [{'function': name, 'pc': pc, 'allowed': list(options)} for (name, pc), options in targets.items()]
        (out / 'call-sites.json').write_text(json.dumps(sites, indent=2) + '\n')
        image = bytearray(max(f['address'] + len(f['code']) for f in functions.values()))
        for function in functions.values():
            offset = function['address']
            image[offset:offset + len(function['code'])] = function['code']
        (out / 'original.bin').write_bytes(image)
        names = list(functions)
        header = [f'#define CODE_BASE UINT64_C({CODE_BASE})', f'#define ENTRY_COUNT {len(functions)}',
                  f'#define LEAF_COUNT {len(LEAVES)}', f'#define CALL_RAX_INDEX {names.index("call_rax")}',
                  f'#define FAILURE_CHAIN_INDEX {names.index("failure_chain")}',
                  'static const uint64_t entry_offsets[] = {' + ','.join(str(f['address']) for f in functions.values()) + '};',
                  'static const uint64_t leaf_targets[] = {' + ','.join(str(CODE_BASE + functions[n]['address']) for n in LEAVES) + '};',
                  '#ifdef ORIGINAL', 'static const unsigned char original_image[] = {']
        header.extend(','.join(str(b) for b in image[offset:offset + 64]) + ','
                      for offset in range(0, len(image), 64))
        header.extend(['};', '#else'])
        header.extend(f'extern void translated_{name}(Cpu *, unsigned char *, unsigned char *, uint64_t);'
                      for name in functions)
        header.append('static void (*entries[])(Cpu *, unsigned char *, unsigned char *, uint64_t) = {'
                      + ','.join(f'translated_{name}' for name in functions) + '};')
        header.append('#endif')
        (out / 'entries.h').write_text('\n'.join(header) + '\n')
        harness = (ROOT / 'indirect_harness.c').read_text()
        if f'#define STACK_BYTES {STACK_BYTES}' not in harness or hex(ROOT_RETURN) not in harness:
            raise ValueError('harness and translator constants differ')
        (out / 'harness.c').write_text(harness)
        (out / 'bridge.s').write_text((ROOT / 'stack_bridge.s').read_text())
        edge = [0, 1, 2, 31, 32, 63, 64, 127, 128, 255, 256, 32767, 32768,
                65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
                (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        pairs = [(a, b) for a in edge for b in edge]
        rng = random.Random(0xbb109)
        pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(256))
        inputs = ''.join(f'{a:016x} {b:016x}\n' for a, b in pairs)
        (out / 'inputs.txt').write_text(inputs)
        outputs, negative_results = {}, {}
        for label, arch in [('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')]:
            original = label == 'original-x86_64'
            exe = out / label
            run(f'build-{label}', ['xcrun', 'clang', '-arch', arch, '-O2',
                                 '-DORIGINAL' if original else '-DTRANSLATED', out / 'harness.c',
                                 out / ('bridge.s' if original else 'indirect.ll'), '-o', exe])
            outputs[label] = run(label, ['/usr/bin/arch', f'-{arch}', exe], inputs).splitlines()
            if not original:
                negative = run(f'{label}-negative', ['/usr/bin/arch', f'-{arch}', exe, '--negative'])
                if 'PASS: 10 invalid-target checks' not in negative:
                    raise RuntimeError('incomplete invalid-target validation')
                negative_results[label] = {'checks': 10, 'status': 'passed'}
        reference = outputs['original-x86_64']
        combinations = len(LEAVES) ** 2
        comparisons = len(pairs) * combinations * len(functions)
        if len(reference) != comparisons:
            raise RuntimeError('incomplete original output')
        for label, rows in outputs.items():
            if rows != reference:
                first = next((i for i, (a, b) in enumerate(zip(reference, rows)) if a != b),
                             min(len(reference), len(rows)))
                report['mismatch'] = {'backend': label, 'row': first}
                if first < comparisons:
                    choice = first // len(functions) % combinations
                    report['mismatch'].update(function=names[first % len(functions)],
                                              inputs=[hex(v) for v in pairs[first // (len(functions) * combinations)]],
                                              targets=[LEAVES[choice // len(LEAVES)], LEAVES[choice % len(LEAVES)]])
                raise RuntimeError(f'{label}: mismatch at row {first}')
        report.update(status='passed', host=platform.platform(), machine=platform.machine(),
                      compiler=run('compiler', ['xcrun', 'clang', '--version']), seed='0xbb109',
                      functions=len(functions), indirect_sites=len(targets), input_pairs=len(pairs),
                      target_pair_combinations=combinations, guest_code_base=hex(CODE_BASE),
                      comparisons_per_aot_backend=comparisons, mismatches=0,
                      negative_results=negative_results,
                      error_codes={'1': 'unregistered guest code address', '2': 'registered but not permitted at this call site'},
                      observed_outputs=['RAX', 'RSI', 'RBX', 'RBP', 'normalized RSP delta', 'memory and guards'],
                      oracle='original x86 indirect CALLs in a fixed-address RX synthetic code image under Rosetta',
                      required_stack_by_function={name: a['required_stack'] for name, a in analyses.items()},
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in ('indirect_lift.py', 'stack_lift.py', 'memory_lift.py',
                                                  'indirect_fixtures.json', 'indirect_harness.c', 'stack_bridge.s',
                                                  'run_indirect.py')},
                      inputs_sha256=hashlib.sha256(inputs.encode()).hexdigest())
        print(f'PASS: {comparisons} indirect-call snapshots per AOT backend, 0 mismatches; 10 negative checks per AOT backend')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(f'FAIL: {error}')
    save()
    print(report_path)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
