#!/usr/bin/env python3
"""Compare common-state branches, indirect calls and synchronous callbacks."""
import argparse
import hashlib
import json
import platform
import random
import struct
import subprocess

from cpu_state import STATE, RFLAGS_INDEX, STATUS_INDEX, c_layout_checks
from gpr_lift import ARITHMETIC_FLAGS
from run_state_stack import (ROOT, CODE_BASE, OUTPUT_BYTES,
                             entry_header, make_record, model, whole_native_bridge)
from state_stack_lift import HOST_IMPORT, lift


def fixtures():
    spec = {}

    def add(name, *parts, **options):
        spec[name] = dict(address=256 * len(spec), parts=list(parts), **options)

    add('leaf_a', '4889f0c3')
    add('leaf_b', '4889d0c3')
    add('leaf_limit', 'ebfec3')
    add('leaf_fault', '488b4740c3')
    add('register_call', '415441ffd0415cc3', indirect_targets={'2': ['leaf_a', 'leaf_b']})
    add('data_call', '53ff175bc3', indirect_targets={'1': ['leaf_a', 'leaf_b']})
    add('stack_call', 'ff542408c3', indirect_targets={'0': ['leaf_a', 'leaf_b']})
    add('nested_indirect', '53', {'call': 'register_call'}, '5bc3')
    add('loop', '4889f14839d1740548ffc9ebf6c3')  # RCX=RSI; while RCX != RDX: --RCX
    add('memory_loop', '4889f14839d1740848890f48ffc9ebf3c3')
    add('loop_call', '4889f1534839d1740a', {'call': 'leaf_b'}, '48ffc9ebf15bc3')
    add('near_jump', 'e9030000004889f04889d0c3')
    add('forever', 'ebfec3')
    for cc in range(16):
        add(f'short_cc{cc}', bytes((0x70 + cc, 3)).hex() + '4889f0c3')
        add(f'near_cc{cc}', bytes((0x0f, 0x80 + cc, 3, 0, 0, 0)).hex() + '4889f0c3')

    def host(name, callee):
        address = len(spec) * 256
        rel = (HOST_IMPORT - address - 6).to_bytes(4, 'little', signed=True)
        add(name, '53e8' + rel.hex() + '5bc3', host_callbacks={'1': callee})

    host('host_reentry', 'leaf_a')
    host('host_fault', 'leaf_fault')
    host('host_budget', 'leaf_limit')
    return spec


def inputs(spec, random_count):
    records = []

    def add(a=3, b=0, flags=0, target=None, *, sp=248, register_target=None, **options):
        address = (CODE_BASE + spec[target]['address']) if isinstance(target, str) else target
        record = make_record(a, b, sp, len(records), **options)
        cpu = list(STATE.unpack(record[:416]))
        cpu[RFLAGS_INDEX] = (cpu[RFLAGS_INDEX] & ~ARITHMETIC_FLAGS) | flags
        if address is not None:
            cpu[8] = cpu[6] = address
            record = record[:496] + struct.pack('<Q', address) + record[504:]
        if register_target is not None:
            cpu[8] = register_target
        records.append(STATE.pack(*cpu) + record[416:])

    for flags in range(64):
        bits = sum(((flags >> i) & 1) << bit for i, bit in enumerate((0, 2, 4, 6, 7, 11)))
        add(flags=bits)
    for target in ('leaf_a', 'leaf_b', 'leaf_limit', 'register_call', 0, CODE_BASE + 1):
        for options in ({}, {'data_rights': 2}, {'stack_rights': 1}, {'stack_rights': 2},
                        {'data_size': 7}, {'stack_size': 252}, {'stack_size': 513}):
            add(target=target, **options)
    for sp in (0, 7, 8, 248, 505):
        add(sp=sp, target='leaf_a')
    for a, b in ((0, 0), (1, 0), (8, 1), (4080, 0), (0, 1)):
        add(a, b)
    rng = random.Random(0xbbc011)
    for _ in range(random_count):
        add(rng.randrange(16), rng.randrange(16), rng.getrandbits(12) & ARITHMETIC_FLAGS,
            register_target=rng.choice([CODE_BASE, CODE_BASE + 256, rng.getrandbits(64)]))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=type(ROOT), default=ROOT.parent / 'out/recompiler-state-control')
    parser.add_argument('--random-count', type=int, default=32)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.random_count < 0: parser.error('--random-count must be nonnegative')
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('use native ARM64 Python on Apple Silicon')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = {'status': 'incomplete', 'commands': []}

    def save():
        (out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')

    def command(label, argv, data=None):
        argv = [str(value) for value in argv]
        report['commands'].append(argv)
        save()
        print(label, flush=True)
        result = subprocess.run(argv, input=data, capture_output=True, timeout=120)
        (out / f'{label}.stderr.log').write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(f'{label} failed ({result.returncode})')
        if data is not None: (out / f'{label}.bin').write_bytes(result.stdout)
        return result.stdout

    save()
    try:
        spec = fixtures()
        ir, functions, decoded, calls, costs = lift(spec)
        program = functions, decoded, calls, costs
        names = list(functions)
        (out / 'state_stack.ll').write_text(ir)
        (out / 'fixtures.json').write_text(json.dumps(spec, indent=2))
        (out / 'cpu_state_layout.h').write_text(c_layout_checks())
        (out / 'state_stack_entries.h').write_text(entry_header(spec, functions))
        (out / 'original.s').write_text(whole_native_bridge(functions, decoded, calls, flag_mask=lambda _: ARITHMETIC_FLAGS))
        records = inputs(spec, args.random_count)
        raw = b''.join(records)
        (out / 'inputs.bin').write_bytes(raw)
        expected = bytearray()
        native_input, native_expected = bytearray(), bytearray()
        counts = [0] * 7
        for record in records:
            for f, name in enumerate(names):
                output = model(program, name, record, spec)
                status = STATE.unpack_from(output)[STATUS_INDEX]
                counts[status] += 1
                expected.extend(output)
                # Host imports have no native guest equivalent. Replay all other
                # successful paths on actual x86 code with real CALL/RET.
                if not status and not spec[name].get('host_callbacks'):
                    native_input.extend(record + struct.pack('<I', f))
                    native_expected.extend(output)
        if not all(counts[i] for i in (0, 1, 2, 3, 5, 6)):
            raise RuntimeError(f'incomplete control outcome coverage: {counts}')
        base = ['xcrun', 'clang', '-O2', '-Wall', '-Wextra', '-I', ROOT, '-I', out,
                ROOT / 'state_stack_harness.c']
        outputs = {}
        for label, arch, source, flags, data, wanted in (
            ('original', 'x86_64', [out / 'original.s'], ['-DORIGINAL', '-DNATIVE_CONTROL'],
             native_input, native_expected),
            ('aot-x86', 'x86_64', [out / 'state_stack.ll', ROOT / 'state_control_bridge.c'], [], raw, expected),
            ('aot-arm', 'arm64', [out / 'state_stack.ll', ROOT / 'state_control_bridge.c'], [], raw, expected),
            ('aot-arm-ubsan', 'arm64', [out / 'state_stack.ll', ROOT / 'state_control_bridge.c'],
             ['-fsanitize=undefined', '-fno-sanitize-recover=all'], raw, expected),
        ):
            if label.endswith('ubsan') and not args.sanitize: continue
            exe = out / label
            command(label + '-build', base + ['-arch', arch, *flags, *source, '-o', exe])
            actual = command(label + '-run', ['/usr/bin/arch', '-' + arch, exe], data)
            if actual != wanted:
                first = next((i for i, (a, b) in enumerate(zip(actual, wanted)) if a != b), min(len(actual), len(wanted)))
                row, offset = divmod(first, OUTPUT_BYTES)
                if label == 'original':
                    start = row * (len(records[0]) + 4) + len(records[0])
                    fixture = names[struct.unpack_from('<I', native_input, start)[0]] if start < len(native_input) else None
                else:
                    fixture = names[row % len(names)]
                raise RuntimeError(f'{label}: mismatch at row {row}, fixture {fixture}, byte {offset}')
            outputs[label] = hashlib.sha256(actual).hexdigest()
        source_names = ('run_state_control.py', 'state_control_bridge.c', 'state_stack_lift.py',
                        'run_state_stack.py', 'state_stack_harness.c', 'state_memory_lift.py',
                        'stack_lift.py', 'memory_lift.py', 'gpr_lift.py', 'run_gpr.py',
                        'cpu_state.py', 'cpu_state.h', 'guest_memory.h')
        report.update(status='passed', fixtures=len(names), inputs=len(records),
                      input_sha256=hashlib.sha256(raw).hexdigest(),
                      expected_sha256=hashlib.sha256(expected).hexdigest(),
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in source_names},
                      snapshots_per_aot_backend=len(expected) // OUTPUT_BYTES,
                      whole_x86_replays=len(native_expected) // OUTPUT_BYTES,
                      outcomes=counts, result_sha256=outputs)
        save()
        print(f"PASS: {report['snapshots_per_aot_backend']} snapshots per AOT backend, "
              f"{report['whole_x86_replays']} whole x86 replays")
    except Exception as exc:
        report.update(status='failed', error=str(exc))
        save()
        raise


if __name__ == '__main__':
    main()
