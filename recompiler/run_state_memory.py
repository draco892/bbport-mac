#!/usr/bin/env python3
"""Compare checked guest mappings and full CPU state on x86 and native ARM64."""
import argparse
import datetime
import gzip
import hashlib
import json
import mmap
import platform
import random
import struct
import subprocess
from pathlib import Path

from cpu_state import STATE, ABI_VERSION, OFFSETS, STATUS_INDEX, c_layout_checks
from state_memory_lift import decode, lift, effective_address, DECLARATIONS, MEMORY_BYTES, MASK64
from run_gpr import make_state, model as gpr_model, oracle_assembly, sha

ROOT = Path(__file__).resolve().parent
BASES = (0x200000010, 0x400000010)
INPUT_BYTES, OUTPUT_BYTES = 544, 528
SEED = 0xbb4d454d


def pack_input(registers, base, size, permissions, null_data, region, index):
    return make_state(index, registers, (index * 0x89) & 0x8d5) + struct.pack('<4Q', base, size, permissions, null_data) + region


def model(code, record):
    state = list(STATE.unpack(record[:STATE.size]))
    base, size, permissions, null_data = struct.unpack('<4Q', record[STATE.size:448])
    region = bytearray(record[448:])
    fault_address = fault_offset = 0
    if size > MEMORY_BYTES or base + size > MASK64 or permissions > 3 or (size and null_data):
        state[STATUS_INDEX] = 2
    else:
        state[STATUS_INDEX] = 0
        for insn in decode(code):
            if insn.op == 'gpr':
                state = list(STATE.unpack(gpr_model(insn.raw + b'\xc3', STATE.pack(*state))))
                continue
            address = effective_address(insn, state[:16])
            length = insn.width // 8
            if address < base or address + length > base + size:
                state[STATUS_INDEX] = 1
            elif not permissions & (2 if insn.op == 'store' else 1):
                state[STATUS_INDEX] = 3
            if state[STATUS_INDEX]:
                fault_address, fault_offset = address, insn.pc
                break
            offset = 16 + address - base
            if insn.op == 'store':
                value = state[insn.reg] & ((1 << insn.width) - 1)
                region[offset:offset + length] = value.to_bytes(length, 'little')
            else:
                value = int.from_bytes(region[offset:offset + length], 'little', signed=insn.op == 'signed_load')
                mask = (1 << insn.destination_width) - 1
                if insn.destination_width < 32:
                    value = (state[insn.reg] & ~mask) | value
                state[insn.reg] = value & (MASK64 if insn.destination_width < 32 else mask)
    return STATE.pack(*state) + struct.pack('<2Q', fault_address, fault_offset) + region


def literal_cases():
    """Full expected snapshots specified independently of the decoder/model."""
    cases = []
    data = bytes.fromhex('80ff0180aa550080') + b'\x5a' * 56
    region = b'\xa5' * 16 + data + b'\xc3' * 16
    sentinel = 0x1122334455667788
    expected_loads = {
        'literal_byte': 0x1122334455667780,
        'literal_word': 0x112233445566ff80,
        'literal_dword': 0x8001ff80,
        'literal_qword': 0x800055aa8001ff80,
        'literal_sx8_32': 0xffffff80,
        'literal_sx8_64': 0xffffffffffffff80,
        'literal_sx16_64': 0xffffffffffffff80,
        'literal_zx16_64': 0xff80,
        'literal_sxd': 0xffffffff8001ff80,
    }

    def add(name, changes=None, *, status=0, address=0, pc=0, registers=None,
            memory=None, size=64, permissions=3, null_data=0, base=BASES[0], arithmetic_flags=None):
        bank = [sentinel + r for r in range(16)]
        bank[0], bank[7] = sentinel, BASES[0]
        if registers:
            for r, value in registers.items(): bank[r] = value
        record = pack_input(bank, base, size, permissions, null_data, region, 100000 + len(cases))
        output = list(STATE.unpack(record[:STATE.size]))
        for r, value in (changes or {}).items(): output[r] = value
        if arithmetic_flags is not None:
            output[49] = (output[49] & ~0x8d5) | arithmetic_flags
        output[STATUS_INDEX] = status
        expected = STATE.pack(*output) + struct.pack('<2Q', address, pc) + (memory if memory is not None else region)
        cases.append((record, name, expected))

    for name, value in expected_loads.items(): add(name, {0: value})
    add('round_trip64', {8: sentinel}, memory=region[:16] + sentinel.to_bytes(8, 'little') + region[24:])
    overlapping = bytearray(region)
    overlapping[16:24] = sentinel.to_bytes(8, 'little')
    overlapping[17:19] = bytes.fromhex('efbe')
    add('overlapping_stores', {8: 0x1122334455beef88}, registers={5: 0xbeef}, memory=overlapping)
    partial = bytearray(region)
    partial[16] = 0x88
    add('store_then_fault', status=1, address=BASES[0] + 64, pc=2, memory=partial)
    add('scalar_then_fault', {0: 0}, registers={0: MASK64, 5: 1}, arithmetic_flags=0x55,
        status=1, address=BASES[0] + 64, pc=3)
    add('scalar_then_fault', registers={0: MASK64, 5: 1}, status=2, size=65)
    add('store_then_fault', status=3, address=BASES[0], permissions=1)
    add('literal_byte', status=3, address=BASES[0], permissions=2)
    add('literal_qword', status=1, address=BASES[0] - 1, registers={7: BASES[0] - 1})
    add('literal_qword', status=1, address=BASES[0] + 57, registers={7: BASES[0] + 57})
    add('literal_qword', {0: 0x5a5a5a5a5a5a5a5a}, registers={7: BASES[0] + 56})
    add('literal_qword', status=2, base=MASK64 - 3)
    add('literal_qword', status=2, permissions=4)
    add('literal_qword', status=2, null_data=1)
    add('scalar_then_fault', {0: 0}, registers={0: MASK64, 5: 1}, arithmetic_flags=0x55,
        status=1, address=BASES[0] + 64, pc=3, size=0, null_data=1)
    add('alias_load64_r7', {7: 0x800055aa8001ff80})
    add('load64_sib_b4_i12_s8', {9: 0x800055aa8001ff80}, registers={4: BASES[0] + 1, 12: 1 << 61})
    add('flags_across_load', {0: 0, 8: 0x8001ff80, 9: 1},
        registers={0: MASK64, 5: 1, 9: 0, 14: 0}, arithmetic_flags=0)
    return cases


def corpus(codes, random_count):
    records, descriptions, directed = [], [], []
    rng = random.Random(SEED)

    def append(registers, base=BASES[0], size=64, permissions=3, null_data=0, description=None, target=None, region=None):
        index = len(records)
        if region is None:
            region = bytes(((i * 37 + index * 13) ^ (0x80 if i & 1 else 0xff)) & 255 for i in range(96))
        record = pack_input(registers, base, size, permissions, null_data, region, index)
        records.append(record)
        descriptions.append(description or {})
        if target: directed.append((index, target))

    for base in BASES:
        for offset in (-129, -1, 0, 1, 2, 7, 15, 31, 55, 56, 57, 62, 63, 64, 65, 127):
            for permissions in (0, 1, 2, 3):
                append([(base + offset) & MASK64 for _ in range(16)], base, permissions=permissions,
                       description={'uniform_offset': offset, 'permissions': permissions})
        for index in (0, 1, 2, 7, 8, 15, MASK64, 1 << 63):
            append([base if r % 2 == 0 else index for r in range(16)], base,
                   description={'sib_index': hex(index)})
    # Every primitive receives directed first-access cases, including the first
    # and last valid address and immediate overrun. Also exercise denial at a
    # valid address, separately from the priority of bounds failures.
    for f, (name, code) in enumerate(codes.items()):
        insn = next(i for i in decode(code) if i.op != 'gpr')
        base = BASES[f & 1]
        length = insn.width // 8
        target_offsets = {-1, 0, 1, 64 - length, 65 - length}
        factor = 1
        if insn.base == insn.index and insn.index is not None:
            factor = 1 + insn.scale
        elif insn.base is None and insn.index is not None:
            factor = insn.scale
        if factor > 1:
            target_offsets.add((insn.displacement - base) % factor)
            target_offsets.add(-1 - ((base - 1 - insn.displacement) % factor))
            overrun = 65 - length
            target_offsets.add(overrun + ((insn.displacement - base - overrun) % factor))
        denial_added = False
        for target_offset in sorted(target_offsets):
            registers = [rng.getrandbits(64) for _ in range(16)]
            wanted = (base + target_offset - insn.displacement) & MASK64
            if insn.base is not None and insn.base == insn.index:
                factor = 1 + insn.scale
                if wanted % factor: continue
                registers[insn.base] = wanted // factor
            elif insn.base is not None:
                registers[insn.base] = wanted
                if insn.index is not None: registers[insn.index] = 0
            elif insn.index is not None:
                if wanted % insn.scale: continue
                registers[insn.index] = wanted // insn.scale
            else:
                continue
            append(registers, base, description={'directed_fixture': name, 'offset': target_offset}, target=name)
            if 0 <= target_offset <= 64 - length and not denial_added:
                append(registers, base, permissions=1 if insn.op == 'store' else 2,
                       description={'denied_fixture': name}, target=name)
                denial_added = True
            if target_offset == 0:
                if insn.index is not None and insn.base is not None and insn.base != insn.index and insn.scale > 1:
                    wrapped = registers.copy()
                    wrapped[insn.index] = 1 << (64 - (insn.scale.bit_length() - 1))
                    append(wrapped, base, description={'wrapped_index_fixture': name}, target=name)
    for base, size, permissions, null_data in (
        (BASES[0], 0, 3, 0), (BASES[0], 0, 3, 1), (BASES[0], 1, 3, 0),
        (BASES[0], 7, 3, 0), (BASES[0], 63, 3, 0), (BASES[0], 65, 3, 0),
        (BASES[0], MASK64, 3, 0), (MASK64 - 3, 64, 3, 0),
        (BASES[0], 64, 4, 0), (BASES[0], 64, MASK64, 0), (BASES[0], 64, 3, 1),
    ):
        append([BASES[0]] * 16, base, size, permissions, null_data,
               description={'descriptor_edge': [hex(base), size, permissions, null_data]})
    for _ in range(random_count):
        base = rng.choice(BASES)
        registers = [rng.getrandbits(64) for _ in range(16)]
        for r in rng.sample(range(16), 8):
            registers[r] = (base + rng.randrange(-8, 72)) & MASK64 if r % 2 == 0 else rng.randrange(0, 16)
        append(registers, base, size=rng.choice((0, 1, 8, 32, 63, 64)), permissions=rng.randrange(4),
               description={'seeded_random': True})
    known = []
    for record, name, expected in literal_cases():
        index = len(records)
        records.append(record)
        descriptions.append({'literal_answer': name})
        known.append((index, name, expected))
        directed.append((index, name))
    return records, descriptions, directed, known


def reference_sources(codes):
    """Separate C bounds/permission checks, then actual x86 instruction bytes."""
    assembly, declarations, functions = [], [], []
    support = '''#include <stdint.h>
#include "cpu_state.h"
#include "guest_memory.h"
static int valid_mapping(BbGuestMemory *m) {
    return m->byte_size <= 64 && m->guest_base <= UINT64_MAX - m->byte_size &&
           !(m->permissions & ~UINT64_C(3)) && (!m->byte_size || m->bytes);
}
static int access_ok(BbCpuState *s, BbGuestMemory *m, uint64_t a, uint64_t n, uint64_t p, uint64_t pc) {
    if (a < m->guest_base || a - m->guest_base > m->byte_size ||
        n > m->byte_size - (a - m->guest_base)) s->status = 1;
    else if (!(m->permissions & p)) s->status = 3;
    else return 1;
    m->fault_address = a; m->fault_offset = pc;
    return 0;
}
'''
    for name, code in codes.items():
        lines = [f'void {name}(BbCpuState *s, BbGuestMemory *m) {{',
                 'm->fault_address = m->fault_offset = 0;',
                 'if (!valid_mapping(m)) { s->status = 2; return; }']
        for insn in decode(code):
            helper = f'{name}_native_{insn.pc}'
            declarations.append(f'extern void {helper}(BbCpuState *);')
            if insn.op == 'gpr':
                assembly.append(oracle_assembly({helper: insn.raw + b'\xc3'}))
            else:
                # Reuse the verified all-GPR capture wrapper. Its placeholder
                # MOV preserves flags just like the memory MOV forms; replace
                # exactly its one raw instruction with the validated fixture.
                wrapper = oracle_assembly({helper: bytes.fromhex('4889c0c3')})
                marker = '.byte 72,137,192'
                if wrapper.count(marker) != 1: raise ValueError('oracle wrapper template changed')
                assembly.append(wrapper.replace(marker, '.byte ' + ','.join(str(v) for v in insn.raw)))
                terms = [f'UINT64_C({insn.displacement & MASK64})']
                if insn.base is not None: terms.append(f's->gpr[{insn.base}]')
                if insn.index is not None: terms.append(f's->gpr[{insn.index}] * UINT64_C({insn.scale})')
                lines += [f'uint64_t a{insn.pc} = ' + ' + '.join(terms) + ';',
                          f'if (!access_ok(s, m, a{insn.pc}, {insn.width // 8}, {2 if insn.op == "store" else 1}, {insn.pc})) return;']
            lines.append(f'{helper}(s);')
        lines += ['s->status = 0;', '}']
        functions.append('\n'.join(lines))
    return '\n'.join(assembly), support + '\n'.join(declarations + functions) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-state-memory')
    parser.add_argument('--random-count', type=int, default=256)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.random_count < 0: parser.error('--random-count must be nonnegative')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'bounded guest-memory map and common CPU state; no game execution',
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'commands': [], 'steps': []}

    def save(): report_path.write_text(json.dumps(report, indent=2) + '\n')

    def command(label, argv, inputs=None):
        argv = [str(arg) for arg in argv]
        print(label, flush=True)
        report['commands'].append(argv)
        save()
        path = out / (label + ('.bin' if inputs is not None else '.stdout.log'))
        with path.open('wb') as stream:
            result = subprocess.run(argv, input=inputs, stdout=stream, stderr=subprocess.PIPE, timeout=300)
        (out / (label + '.stderr.log')).write_bytes(result.stderr)
        report['steps'].append({'name': label, 'exit_code': result.returncode})
        save()
        if result.returncode: raise RuntimeError(f'{label}: exit {result.returncode}; see stderr log')
        return path

    save()
    try:
        if platform.system() != 'Darwin' or platform.machine() != 'arm64': raise RuntimeError('use native ARM64 Python on Apple Silicon')
        fixtures = json.loads((ROOT / 'state_memory_fixtures.json').read_text())
        codes = {name: bytes.fromhex(code) for name, code in fixtures.items()}
        names = list(codes)
        (out / 'state_memory.ll').write_text(DECLARATIONS + '\n\n'.join(lift(code, name) for name, code in codes.items()))
        assembly, source = reference_sources(codes)
        (out / 'original.s').write_text(assembly)
        (out / 'original.c').write_text(source)
        (out / 'cpu_state_layout.h').write_text(c_layout_checks())
        (out / 'state_memory_functions.h').write_text('#define STATE_MEMORY_FUNCTIONS(X) \\\n' + ' \\\n'.join(f' X({name})' for name in names) + '\n')
        records, descriptions, directed, known = corpus(codes, args.random_count)
        inputs = b''.join(records)
        (out / 'inputs.bin').write_bytes(inputs)
        (out / 'inputs.json').write_text(json.dumps(descriptions, indent=2) + '\n')
        (out / 'known-answers.json').write_text(json.dumps([
            dict(input_index=i, function=name, expected=expected.hex()) for i, name, expected in known], indent=2) + '\n')
        outputs = {}
        for label, arch in (('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')):
            argv = ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2', '-Wall', '-Wextra', '-I', ROOT, '-I', out,
                    ROOT / 'state_memory_harness.c']
            argv += ['-DORIGINAL', out / 'original.s', out / 'original.c'] if label.startswith('original') else [out / 'state_memory.ll']
            exe = out / label
            command(label + '-build', argv + ['-o', exe])
            outputs[label] = command(label + '-run', ['/usr/bin/arch', '-' + arch, exe], inputs)
            if args.sanitize and arch == 'arm64':
                exe = out / 'aot-arm64-ubsan'
                command('aot-arm64-ubsan-build', argv + ['-fsanitize=undefined', '-fno-sanitize-recover=all', '-o', exe])
                outputs['aot-arm64-ubsan'] = command('aot-arm64-ubsan-run', ['/usr/bin/arch', '-arm64', exe], inputs)
        expected_size = len(records) * len(names) * OUTPUT_BYTES
        for label, path in outputs.items():
            if path.stat().st_size != expected_size: raise RuntimeError(f'{label}: incomplete snapshots')
            with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                for index, name, expected in known:
                    position = (index * len(names) + names.index(name)) * OUTPUT_BYTES
                    if data[position:position + OUTPUT_BYTES] != expected:
                        (out / 'known-mismatch.json').write_text(json.dumps(dict(backend=label, function=name, input_index=index,
                            expected=expected.hex(), actual=data[position:position + OUTPUT_BYTES].hex()), indent=2))
                        raise RuntimeError(f'{label}: literal answer mismatch at {name}')
        reference = outputs['original-x86_64']
        for label, path in outputs.items():
            with reference.open('rb') as left, path.open('rb') as right:
                offset = 0
                while a := left.read(1024 * 1024):
                    b = right.read(len(a))
                    if a != b:
                        first = offset + next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
                        index, f = divmod(first // OUTPUT_BYTES, len(names))
                        report['mismatch'] = {'backend': label, 'input_index': index, 'input': descriptions[index], 'function': names[f],
                                              'snapshot_byte': first % OUTPUT_BYTES}
                        raise RuntimeError(f'{label}: mismatch at {names[f]}, input {index}')
                    offset += len(a)
        independent, outcome_counts, coverage = 0, [0] * 4, {name: [0] * 4 for name in names}
        name_index = {name: f for f, name in enumerate(names)}
        with reference.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            # Every fixture on selected shared cases; every individually directed
            # target case; all malformed/edge descriptors on every fixture.
            pairs = {(i, f) for i in range(0, len(records), 19) for f in range(len(names))}
            pairs.update((i, name_index[name]) for i, name in directed)
            pairs.update((i, f) for i, d in enumerate(descriptions) if 'descriptor_edge' in d for f in range(len(names)))
            for index, f in sorted(pairs):
                expected = model(codes[names[f]], records[index])
                position = (index * len(names) + f) * OUTPUT_BYTES
                if data[position:position + OUTPUT_BYTES] != expected:
                    report['model_mismatch'] = dict(function=names[f], input_index=index, input=descriptions[index])
                    raise RuntimeError(f'independent model mismatch at {names[f]}, input {index}')
                independent += 1
            for i in range(len(records)):
                for f, name in enumerate(names):
                    position = (i * len(names) + f) * OUTPUT_BYTES + OFFSETS['status']
                    status, = struct.unpack('<I', data[position:position + 4])
                    outcome_counts[status] += 1
                    coverage[name][status] += 1
        uncovered_primitives = [name for name, code in codes.items() if len(decode(code)) == 1
                                and any(not coverage[name][status] for status in (0, 1, 2, 3))]
        if uncovered_primitives: raise RuntimeError(f'primitive missing success/fault coverage: {uncovered_primitives}')
        hashes = {name: sha(path) for name, path in outputs.items()}
        if len(set(hashes.values())) != 1: raise RuntimeError('result hashes differ')
        print('archive-results', flush=True)
        archive = out / ('snapshots-' + hashes['original-x86_64'] + '.bin.gz')
        with reference.open('rb') as src, gzip.open(archive, 'wb', compresslevel=1) as dst:
            while chunk := src.read(4 * 1024 * 1024): dst.write(chunk)
        with gzip.open(archive, 'rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != hashes['original-x86_64']: raise RuntimeError('archive round-trip mismatch')
        report.update(host=platform.platform(), machine=platform.machine(), cpu_state_abi=ABI_VERSION, cpu_state_bytes=STATE.size,
                      input_record_bytes=INPUT_BYTES, snapshot_bytes=OUTPUT_BYTES, guest_region_bytes=MEMORY_BYTES,
                      seed=hex(SEED), fixtures=len(codes), input_states=len(records), comparisons_per_aot_backend=len(records) * len(names),
                      mismatches=0, native_ubsan=args.sanitize, independent_model_snapshots=independent,
                      outcome_counts=dict(zip(('success', 'bounds', 'invalid_descriptor', 'permission_denied'), outcome_counts)),
                      per_fixture_outcomes=coverage, directed_model_snapshots=len(directed), literal_answers_per_backend=len(known),
                      oracle='Independent C checks, then original x86 instruction bytes at exact verified guest mappings under Rosetta.',
                      source_sha256={str((ROOT / name).relative_to(ROOT.parent)): sha(ROOT / name) for name in
                          ('state_memory_lift.py', 'guest_memory.h', 'state_memory_harness.c', 'run_state_memory.py',
                           'state_memory_fixtures.json', 'cpu_state.h', 'cpu_state.py', 'gpr_lift.py', 'run_gpr.py')},
                      inputs_sha256=sha(out / 'inputs.bin'), results_sha256=hashes,
                      result_archive=dict(path=archive.name, compression='gzip', sha256=sha(archive),
                                          uncompressed_sha256=hashes['original-x86_64'], uncompressed_bytes=expected_size))
        compiler = command('compiler', ['xcrun', 'clang', '--version'])
        report['compiler'] = compiler.read_text()
        report['status'] = 'passed'
        save()
        for path in outputs.values(): path.unlink()
        print(f'PASS: {len(records) * len(names)} CPU/memory snapshots per AOT backend, zero differences; {report_path}', flush=True)
    except Exception as error:
        report.update(status='failed', error=str(error))
        save()
        raise


if __name__ == '__main__': main()
