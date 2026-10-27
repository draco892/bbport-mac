#!/usr/bin/env python3
"""Differential synchronous host/guest callback validation on Apple Silicon."""
import argparse
import hashlib
import json
import platform
import random
import subprocess
from pathlib import Path

from callback_lift import HOST_IMPORTS, lift_callbacks
from indirect_lift import CODE_BASE
from stack_lift import ROOT_RETURN, STACK_BYTES

ROOT = Path(__file__).resolve().parent
CALLBACKS = ('callback_add', 'callback_service', 'callback_frame', 'callback_twice',
             'callback_chain', 'callback_indirect')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-callback')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('run with native ARM64 Python on Apple Silicon')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'synthetic synchronous scalar host/guest callbacks',
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
        ir, analyses, functions, targets = lift_callbacks(json.loads((ROOT / 'callback_fixtures.json').read_text()))
        (out / 'callback.ll').write_text(ir + '\n')
        manifest = {'guest_functions': {name: {'offset': f['address'], 'guest_address': CODE_BASE + f['address'],
                                               'code': f['code'].hex()} for name, f in functions.items()},
                    'host_imports': {name: {'offset': address, 'guest_address': CODE_BASE + address}
                                     for name, address in HOST_IMPORTS.items()},
                    'callbacks': list(CALLBACKS),
                    'indirect_sites': [{'function': n, 'pc': pc, 'allowed': list(t)} for (n, pc), t in targets.items()]}
        (out / 'module.json').write_text(json.dumps(manifest, indent=2) + '\n')
        image = bytearray(max([f['address'] + len(f['code']) for f in functions.values()]
                              + [address + 12 for address in HOST_IMPORTS.values()]))
        for function in functions.values():
            address = function['address']
            image[address:address + len(function['code'])] = function['code']
        for address in HOST_IMPORTS.values():
            image[address:address + 12] = b'\x48\xb8' + b'\x00' * 8 + b'\xff\xe0'
        (out / 'original.bin').write_bytes(image)
        header = [f'#define CODE_BASE UINT64_C({CODE_BASE})', f'#define ENTRY_COUNT {len(functions)}',
                  f'#define CALLBACK_COUNT {len(CALLBACKS)}', f'#define HOST_IMPORT_OFFSET {HOST_IMPORTS["host_service"]}',
                  f'#define HOST_IMPORT_ADDRESS UINT64_C({CODE_BASE + HOST_IMPORTS["host_service"]})',
                  f'#define GUEST_LEAF_ADDRESS UINT64_C({CODE_BASE + functions["guest_leaf"]["address"]})',
                  f'#define GUEST_HELPER_ADDRESS UINT64_C({CODE_BASE + functions["guest_helper"]["address"]})',
                  f'#define CALLBACK_CHAIN_ADDRESS UINT64_C({CODE_BASE + functions["callback_chain"]["address"]})',
                  'static const uint64_t entry_offsets[] = {' + ','.join(str(f['address']) for f in functions.values()) + '};',
                  'static const uint64_t callback_targets[] = {' + ','.join(str(CODE_BASE + functions[n]['address']) for n in CALLBACKS) + '};',
                  '#ifdef ORIGINAL', 'static const unsigned char original_image[] = {']
        header.extend(','.join(str(b) for b in image[offset:offset + 64]) + ','
                      for offset in range(0, len(image), 64))
        header.extend(['};', '#endif'])
        (out / 'entries.h').write_text('\n'.join(header) + '\n')
        harness = (ROOT / 'callback_harness.c').read_text()
        if f'#define STACK_BYTES {STACK_BYTES}' not in harness or hex(ROOT_RETURN) not in harness:
            raise ValueError('harness and translator constants differ')
        (out / 'harness.c').write_text(harness)
        for name in ('stack_bridge.s', 'callback_bridge.s'):
            (out / name).write_text((ROOT / name).read_text())
        edge = [0, 1, 2, 31, 32, 63, 64, 127, 128, 255, 256, 32767, 32768,
                65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
                (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        pairs = [(a, b) for a in edge for b in edge]
        rng = random.Random(0xbb109)
        pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(256))
        inputs = ''.join(f'{a:016x} {b:016x}\n' for a, b in pairs)
        (out / 'inputs.txt').write_text(inputs)
        outputs, negatives = {}, {}
        for label, arch in [('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')]:
            original = label == 'original-x86_64'
            exe = out / label
            sources = [out / 'stack_bridge.s', out / 'callback_bridge.s'] if original else [out / 'callback.ll']
            run(f'build-{label}', ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2',
                                 '-DORIGINAL' if original else '-DTRANSLATED', out / 'harness.c', *sources, '-o', exe])
            outputs[label] = run(label, ['/usr/bin/arch', f'-{arch}', exe], inputs).splitlines()
            if not original:
                result = run(f'{label}-negative', ['/usr/bin/arch', f'-{arch}', exe, '--negative'])
                if 'PASS: 10 callback rejection/recovery checks' not in result:
                    raise RuntimeError('incomplete callback rejection/recovery validation')
                negatives[label] = {'checks': 10, 'status': 'passed'}
        reference = outputs['original-x86_64']
        per_pair = len(CALLBACKS) * 3 * 2 * 2
        comparisons = len(pairs) * per_pair
        if len(reference) != comparisons:
            raise RuntimeError('incomplete original callback output')
        for label, rows in outputs.items():
            if rows != reference:
                first = next((i for i, (a, b) in enumerate(zip(reference, rows)) if a != b),
                             min(len(reference), len(rows)))
                report['mismatch'] = {'backend': label, 'row': first}
                if first < comparisons:
                    variant = first % per_pair
                    report['mismatch'].update(callback=CALLBACKS[variant // 12], inner=CALLBACKS[variant // 4 % 3],
                                              reenter=bool(variant // 2 % 2), repeat=variant % 2,
                                              inputs=[hex(v) for v in pairs[first // per_pair]])
                raise RuntimeError(f'{label}: callback mismatch at row {first}')
        report.update(status='passed', host=platform.platform(), machine=platform.machine(),
                      compiler=run('compiler', ['xcrun', 'clang', '--version']), seed='0xbb109',
                      guest_functions=len(functions), callback_entries=len(CALLBACKS), host_imports=len(HOST_IMPORTS),
                      input_pairs=len(pairs), comparisons_per_aot_backend=comparisons, mismatches=0,
                      negative_results=negatives,
                      observed_outputs=['RAX', 'RSI', 'RBX', 'RBP', 'normalized SP', 'memory and guards',
                                        'transition trace hash', 'callback/service counts', 'maximum callback depth'],
                      error_codes={'1': 'unknown guest address', '2': 'not allowed as a callback',
                                   '3': 'inactive or invalid registration handle', '4': 'callback depth limit',
                                   '5': 'bridge invariant failure'},
                      required_stack_by_function={n: a['required_stack'] for n, a in analyses.items()},
                      oracle='original x86 fixtures with a native C host import and real x86 callback bridges under Rosetta',
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in ('callback_lift.py', 'callback_harness.c', 'callback_fixtures.json',
                                                  'callback_bridge.s', 'stack_bridge.s', 'run_callback.py',
                                                  'indirect_lift.py', 'stack_lift.py', 'memory_lift.py')},
                      inputs_sha256=hashlib.sha256(inputs.encode()).hexdigest())
        print(f'PASS: {comparisons} callback snapshots per AOT backend, 0 mismatches; 10 rejection/recovery checks per AOT backend')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(f'FAIL: {error}')
    save()
    print(report_path)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
