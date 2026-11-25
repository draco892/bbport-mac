#!/usr/bin/env python3
"""Measure local PS4 function coverage and compare safe leaves across CPU engines."""
import argparse
from collections import Counter
import ctypes
import hashlib
import json
import mmap
from pathlib import Path
import platform
import random
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_REG_RIP, X86_REG_EIP
import capstone
import unicorn
from unicorn import x86_const

from cpu_state import GPR_NAMES, RFLAGS_INDEX, STATE, STATUS_INDEX, c_layout_checks
import gpr_lift
from run_gpr import make_state, oracle_assembly
from state_stack_lift import decode

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'scripts'))
from prepare import parse_self

IMAGES = ('eboot.bin', 'sce_module/libc.prx', 'sce_module/libSceFios2.prx')
FLAGS = gpr_lift.ARITHMETIC_FLAGS


def digest(data):
    return hashlib.sha256(data).hexdigest()


def mapped_offset(headers, address, size, executable=False):
    for h in headers:
        offset = address - h['vaddr']
        if h['type'] == 1 and 0 <= offset <= h['filesz'] - size and (
                not executable or h['flags'] & 1):
            return h['offset'] + offset
    raise ValueError('address outside file-backed load segments')


def leb_end(data, position, end):
    for _ in range(10):
        if position >= end:
            raise ValueError('truncated CIE integer')
        position += 1
        if not data[position - 1] & 0x80:
            return position
    raise ValueError('oversized CIE integer')


def cie_encoding(data, offset):
    length, cie_id, version = struct.unpack_from('<IIB', data, offset)
    end = offset + 4 + length
    if cie_id or version != 1 or end > len(data):
        raise ValueError('unsupported CIE format')
    start = offset + 9
    zero = data.index(0, start, end)
    augmentation = bytes(data[start:zero])
    if not augmentation.startswith(b'z'):
        raise ValueError('unsupported CIE augmentation')
    pos = leb_end(data, zero + 1, end)
    pos = leb_end(data, pos, end) + 1  # data alignment and v1 return-register byte
    pos = leb_end(data, pos, end)  # length of augmentation data
    for item in augmentation[1:]:
        if pos >= end:
            raise ValueError('truncated CIE augmentation')
        encoding = data[pos]
        pos += 1
        if item == ord('R'):
            return encoding
        if item == ord('P'):
            width = {0: 8, 2: 2, 3: 4, 4: 8, 10: 2, 11: 4, 12: 8}.get(encoding & 15)
            if width is None:
                raise ValueError('unsupported CIE personality encoding')
            pos += width
        elif item != ord('L'):
            raise ValueError('unsupported CIE augmentation item')
    raise ValueError('missing CIE range encoding')


def function_ranges(data, headers):
    """Read the observed GNU EH-frame index and validate each FDE range."""
    hdr = next(h for h in headers if h['type'] == 0x6474e550)
    start, base = hdr['offset'], hdr['vaddr']
    if data[start:start + 4] != b'\x01\x1b\x03\x3b':
        raise ValueError('unsupported EH-frame index encoding')
    count, = struct.unpack_from('<I', data, start + 8)
    if 12 + count * 8 > hdr['filesz']:
        raise ValueError('truncated EH-frame index')
    ranges, rejected, encodings = set(), Counter(), {}
    for start_delta, fde_delta in struct.iter_unpack('<ii', memoryview(data)[start + 12:start + 12 + count * 8]):
        address, fde = base + start_delta, base + fde_delta
        try:
            file_offset = mapped_offset(headers, fde, 16)
            length, cie_delta, pc_delta, size = struct.unpack_from('<IIiI', data, file_offset)
            if length < 12 or length == 0xffffffff or not cie_delta:
                raise ValueError('unsupported FDE layout')
            mapped_offset(headers, fde, length + 4)
            cie = mapped_offset(headers, fde + 4 - cie_delta, 9)
            if cie not in encodings:
                encodings[cie] = cie_encoding(data, cie)
            if encodings[cie] != 0x1b:
                raise ValueError('unsupported FDE pointer encoding')
            if not size or address != fde + 8 + pc_delta:
                raise ValueError('inconsistent FDE range')
            offset = mapped_offset(headers, address, size, executable=True)
            ranges.add((address, size, offset))
        except ValueError as exc:
            rejected[str(exc)] += 1
    return sorted(ranges), count, rejected


def supported_instruction(raw):
    try:
        instructions = decode(raw if raw == b'\xc3' else raw + b'\xc3', real=True)
        return len(instructions) == (1 if raw == b'\xc3' else 2)
    except ValueError:
        return False


def function_contract(raw):
    try:
        instructions = decode(raw, real=True)
    except ValueError:
        return 'decoder_rejected'
    boundaries = {i.pc for i in instructions}
    if any(i.op == 'branch' and i.target not in boundaries for i in instructions):
        return 'out_of_function_branch'
    if any(i.op in ('call', 'indirect') for i in instructions):
        return 'requires_call_resolution'
    return 'standalone_contract'


def select_leaves(data, ranges, disassembler, limit, pinned=()):
    """Allow only straight-line register operations to reach the x86 oracle."""
    picks = {'llvm': [], 'unicorn_only': []}
    seen = set()
    pinned = set(pinned)
    ordered = sorted(ranges, key=lambda interval: interval[0] not in pinned) if pinned else ranges
    for address, size, offset in ordered:
        if address not in pinned and all(len(group) >= limit for group in picks.values()):
            break
        if not 2 <= size <= 32:
            continue
        raw = bytes(data[offset:offset + size])
        if (raw in seen and address not in pinned) or raw[-1] != 0xc3:
            continue
        decoded = list(disassembler.disasm(raw, address))
        if (len(decoded) < 2 or sum(i.size for i in decoded) != size or
                bytes(decoded[-1].bytes) != b'\xc3'):
            continue
        body = decoded[:-1]
        try:
            gpr_lift.decode(raw)
            tier = 'llvm'
        except ValueError:
            tier = 'unicorn_only'
        if address not in pinned and len(picks[tier]) >= limit:
            continue
        if any(i.mnemonic not in ('mov', 'movabs', 'movsx', 'movsxd', 'movzx', 'lea', 'add', 'sub', 'xor', 'and',
                                  'or', 'inc', 'dec', 'cmp', 'test', 'adc', 'sbb',
                                  'shl', 'shr', 'sar', 'rol', 'ror')
               or any(i.reg_name(r) in ('rsp', 'esp', 'sp', 'spl') for r in i.regs_access()[1])
               or any(o.type == X86_OP_MEM and (i.mnemonic != 'lea' or
                      o.mem.segment or o.mem.base in (X86_REG_RIP, X86_REG_EIP))
                      for o in i.operands) for i in body):
            continue
        if tier == 'unicorn_only' and any(i.mnemonic not in ('mov', 'movabs', 'lea') for i in body):
            continue
        # Exclude moves/LEA involving noninteger registers, e.g. MOV to a segment.
        if any(any(r not in {'eflags', *INTEGER_ALIASES} for r in
                   (i.reg_name(reg) for reg in sum(i.regs_access(), []) +
                    [op.reg for op in i.operands if op.type == X86_OP_REG]))
               for i in body):
            continue
        seen.add(raw)
        picks[tier].append((address, raw))
    return picks


INTEGER_ALIASES = set(GPR_NAMES) | {
    'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
    'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
    'al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil', 'ah', 'ch', 'dh', 'bh',
} | {r + suffix for r in GPR_NAMES[8:] for suffix in ('d', 'w', 'b')}


def measure(image, disassembler, sample_count, leaf_count, pinned=()):
    data = image.read_bytes()
    payload, header, headers, _, _ = parse_self(data, image.name)
    ranges, indexed, rejected = function_ranges(payload, headers)
    if not ranges:
        raise ValueError('no valid FDE ranges')
    eligible = [item for item in ranges if item[1] <= 8192]
    if not eligible:
        raise ValueError('no FDE ranges within the sample size limit')
    count = min(sample_count, len(eligible))
    selected = {eligible[i * len(eligible) // count] for i in range(count)}
    selected.update(item for item in eligible if item[0] == header[4])
    instructions, missing, functions = Counter(), Counter(), Counter()
    total, decoded_bytes = 0, 0
    for address, size, offset in sorted(selected):
        raw = bytes(payload[offset:offset + size])
        functions[function_contract(raw)] += 1
        for insn in disassembler.disasm(raw, address):
            if insn.id == 0:
                continue  # Capstone skipdata resynchronization is counted separately.
            total += 1
            decoded_bytes += insn.size
            mnemonic = insn.mnemonic
            if supported_instruction(bytes(insn.bytes)):
                instructions[mnemonic] += 1
            else:
                missing[mnemonic] += 1
    return {
        'input_sha256': digest(data), 'fde_index_entries': indexed,
        'distinct_file_backed_ranges': len(ranges), 'rejected_fde_entries': dict(rejected),
        'eligible_ranges': len(eligible), 'sampled_ranges': len(selected),
        'sampled_bytes': sum(size for _, size, _ in selected), 'decoded_bytes': decoded_bytes,
        'decoded_instructions': total, 'accepted_instruction_encodings': instructions.total(),
        'whole_range_contract': dict(functions), 'top_unsupported_mnemonics': missing.most_common(15),
    }, select_leaves(payload, ranges, disassembler, leaf_count, pinned)


def compare_leaves(leaves, out, input_count, emit_aot=False):
    rng = random.Random(0xbb109)
    edge = [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, 0x7fffffff, 0x80000000,
            0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000,
            0xffffffffffffffff]
    records = [
        make_state(i, [edge[(i + reg) % len(edge)] if i < len(edge)
                       else rng.getrandbits(64) for reg in range(16)],
                   rng.getrandbits(12) & FLAGS)
        for i in range(input_count)
    ]
    names = list(leaves)
    llvm_names = [name for name in names if leaves[name]['tier'] == 'llvm']
    if not llvm_names:
        raise ValueError('no LLVM-compatible leaves')
    commands = []

    def executable(directory, label, arch, codes, source_name, source):
        macro = '#define GPR_FUNCTIONS(X) ' + ' \\\n'.join(f'X({name})' for name in codes) + '\n'
        (directory / 'gpr_functions.h').write_text(macro)
        src = directory / source_name
        if source is not None:
            src.write_text(source)
        exe = directory / label
        command = ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2', '-I', str(ROOT),
                   '-I', str(directory), str(ROOT / 'gpr_harness.c'), str(src), '-o', str(exe)]
        commands.append([label, 'clang', arch, source_name])
        subprocess.run(command, check=True, capture_output=True, timeout=60)
        proc = subprocess.run(['/usr/bin/arch', '-' + arch, exe], input=b''.join(records),
                              check=True, capture_output=True, timeout=60)
        if len(proc.stdout) != input_count * len(codes) * STATE.size:
            raise ValueError('incomplete oracle output')
        return proc.stdout

    with tempfile.TemporaryDirectory(prefix='private-leaf-oracles-', dir=out) as tmp:
        directory = Path(tmp)
        (directory / 'cpu_state_layout.h').write_text(c_layout_checks())
        native_sources = []
        for name, leaf in leaves.items():
            raw = leaf['code']
            if leaf['tier'] == 'llvm':
                native_sources.append(oracle_assembly({name: raw}))
            else:
                register_mov = bytes.fromhex('4889c0c3')
                wrapper = oracle_assembly({name: register_mov})
                marker = '.byte 72,137,192'
                if wrapper.count(marker) != 1:
                    raise ValueError('x86 wrapper template changed')
                native_sources.append(wrapper.replace(marker, '.byte ' + ','.join(map(str, raw[:-1]))))
        reference = executable(directory, 'original', 'x86_64', names, 'oracle.s', '\n'.join(native_sources))
        ir = gpr_lift.DECLARATIONS + '\n'.join(gpr_lift.lift(leaves[name]['code'], name) for name in llvm_names)
        if emit_aot:
            (directory / 'llvm.ll').write_text(ir)
            obj = directory / 'real-leaves-arm64.o'
            subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O2', '-c',
                            directory / 'llvm.ll', '-o', obj], check=True, capture_output=True, timeout=60)
            architecture = subprocess.check_output(['lipo', '-archs', obj], text=True).strip()
            if architecture != 'arm64':
                raise ValueError('unexpected object architecture')
            object_bytes = obj.read_bytes()
            llvm = executable(directory, 'llvm', 'arm64', llvm_names, obj.name, None)
        else:
            llvm = executable(directory, 'llvm', 'arm64', llvm_names, 'llvm.ll', ir)

    register_ids = [getattr(x86_const, f'UC_X86_REG_{name.upper()}') for name in GPR_NAMES]
    mismatches = []
    matches = Counter()
    for j, (name, leaf) in enumerate(leaves.items()):
        raw = leaf['code']
        arch = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        base = 0x100000
        arch.mem_map(base, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        arch.mem_write(base, raw[:-1])
        defined = gpr_lift.defined_flags(raw) if leaf['tier'] == 'llvm' else FLAGS
        llvm_index = llvm_names.index(name) if name in llvm_names else None
        for i, record in enumerate(records):
            state = list(STATE.unpack(record))
            arch.reg_write_batch(tuple(zip(register_ids, state[:16])))
            arch.reg_write(x86_const.UC_X86_REG_RFLAGS, 0x202 | (state[RFLAGS_INDEX] & FLAGS))
            arch.emu_start(base, base + len(raw) - 1, timeout=100_000, count=len(raw))
            if arch.reg_read(x86_const.UC_X86_REG_RIP) != base + len(raw) - 1:
                raise RuntimeError('Unicorn did not reach the end of a leaf')
            state[:16] = arch.reg_read_batch(register_ids)
            state[RFLAGS_INDEX] = ((state[RFLAGS_INDEX] & ~FLAGS) |
                                   (arch.reg_read(x86_const.UC_X86_REG_RFLAGS) & defined))
            state[STATUS_INDEX] = 0
            offset = (i * len(names) + j) * STATE.size
            wanted = reference[offset:offset + STATE.size]
            if STATE.pack(*state) != wanted:
                mismatches.append({'engine': 'unicorn', 'leaf': name, 'input': i})
            else:
                matches['unicorn_' + leaf['tier']] += 1
            if llvm_index is not None:
                offset = (i * len(llvm_names) + llvm_index) * STATE.size
                if llvm[offset:offset + STATE.size] != wanted:
                    mismatches.append({'engine': 'llvm_arm64', 'leaf': name, 'input': i})
                else:
                    matches['llvm_arm64'] += 1
    artifact = None
    if emit_aot and not mismatches:
        path = out / 'real-leaves-arm64.o'
        path.write_bytes(object_bytes)
        artifact = {'filename': path.name, 'architecture': architecture,
                    'sha256': digest(object_bytes), 'symbols': llvm_names}
    return {
        'aot_object': artifact,
        'inputs_per_leaf': input_count, 'matches': dict(matches), 'mismatches': mismatches,
        'native_builds': commands, 'inputs_sha256': digest(b''.join(records)),
        'x86_reference_sha256': digest(reference), 'llvm_results_sha256': digest(llvm),
        'leaves': {name: {key: value for key, value in item.items() if key != 'code'}
                   | {'byte_count': len(item['code']), 'code_sha256': digest(item['code'])}
                   for name, item in leaves.items()},
    }


def compatibility_probe():
    """Exercise a host-owned mapping and synchronous CPU faults on native ARM64."""
    code, data = 0x100000, 0x200000
    page_size = mmap.PAGESIZE
    with mmap.mmap(-1, page_size) as backing:
        pointer = ctypes.addressof(ctypes.c_ubyte.from_buffer(backing))
        first, second = (unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64) for _ in range(2))
        try:
            for engine in (first, second):
                engine.mem_map(code, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
                engine.mem_write(code, bytes.fromhex('4887070f0b'))  # XCHG [RDI], RAX; UD2
                engine.mem_map_ptr(data, page_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE, pointer)
                engine.reg_write(x86_const.UC_X86_REG_RDI, data)
            struct.pack_into('<Q', backing, 0, 7)

            def exchange(engine, value, expected):
                engine.reg_write(x86_const.UC_X86_REG_RAX, value)
                engine.emu_start(code, code + 3, timeout=100_000, count=1)
                if (engine.reg_read(x86_const.UC_X86_REG_RAX) != expected or
                        struct.unpack_from('<Q', backing)[0] != value):
                    raise RuntimeError('host-backed memory exchange mismatch')

            exchange(first, 9, 7)
            exchange(second, 11, 9)
            second.mem_protect(data, page_size, unicorn.UC_PROT_READ)

            def expect_fault(engine, pc, length, error):
                try:
                    engine.emu_start(pc, pc + length, timeout=100_000, count=1)
                except unicorn.UcError as exc:
                    if exc.errno == error and engine.reg_read(x86_const.UC_X86_REG_RIP) == pc:
                        return
                    raise
                raise RuntimeError('expected Unicorn fault did not occur')

            expect_fault(second, code, 3, unicorn.UC_ERR_WRITE_PROT)
            if struct.unpack_from('<Q', backing)[0] != 11:
                raise RuntimeError('denied exchange changed host memory')
            expect_fault(first, code + 3, 2, unicorn.UC_ERR_INSN_INVALID)
            expect_fault(first, 0x300000, 1, unicorn.UC_ERR_FETCH_UNMAPPED)
        finally:
            first.mem_unmap(data, page_size)
            second.mem_unmap(data, page_size)
    return {'sequential_shared_host_backing': True, 'denied_write_preserves_memory': True,
            'ud2_precise_rip': True, 'unmapped_fetch_precise_rip': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/cpu-real-audit')
    parser.add_argument('--sample', type=int, default=96)
    parser.add_argument('--leaves-per-tier', type=int, default=4)
    parser.add_argument('--inputs', type=int, default=128)
    parser.add_argument('--baseline', type=Path, help='also retest leaf offsets from a prior audit')
    parser.add_argument('--emit-aot', action='store_true', help='retain a verified local ARM64 Mach-O object')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('use native ARM64 Python and an Apple Silicon Mac with Rosetta')
    if not 1 <= args.sample <= 2048 or not 1 <= args.leaves_per_tier <= 16 or not 13 <= args.inputs <= 4096:
        parser.error('sample must be 1..2048, leaves per tier 1..16 and inputs 13..4096')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'host': platform.platform(), 'capstone': capstone.__version__,
              'unicorn': unicorn.__version__, 'machine': platform.machine(), 'images': {}}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    save()
    if args.emit_aot:
        (out / 'real-leaves-arm64.o').unlink(missing_ok=True)
    try:
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.detail = True
        cs.skipdata = True
        report['sources_sha256'] = {p.name: digest(p.read_bytes()) for p in
                                    (Path(__file__), ROOT / 'state_stack_lift.py', ROOT / 'gpr_lift.py',
                                     ROOT / 'state_memory_lift.py', ROOT / 'simd_lift.py',
                                     ROOT / 'run_gpr.py', ROOT / 'cpu_state.py', ROOT / 'cpu_state.h', ROOT / 'x86_address.py',
                                     ROOT / 'gpr_harness.c', ROOT.parent / 'scripts' / 'prepare.py')}
        baseline = json.loads(args.baseline.read_text()) if args.baseline else None
        previous = (baseline['differential']['leaves'] if baseline else {}).values()
        leaves = {}
        for i, name in enumerate(IMAGES):
            pinned = {int(item['address'], 16) for item in previous if item['image'] == name}
            result, picked = measure(args.game / name, cs, args.sample, args.leaves_per_tier, pinned)
            if baseline and baseline['images'][name]['input_sha256'] != result['input_sha256']:
                raise ValueError(f'{name}: baseline image hash mismatch')
            report['images'][name] = result
            for tier, group in picked.items():
                for j, (address, code) in enumerate(group):
                    leaves[f'leaf_{i}_{tier}_{j}'] = dict(image=name, address=hex(address), tier=tier, code=code)
            print(f"{name}: {result['accepted_instruction_encodings']}/{result['decoded_instructions']} "
                  f"encodings, {result['whole_range_contract']}", flush=True)
        current = {(item['image'], item['address']): item for item in leaves.values()}
        for old in previous:
            item = current.get((old['image'], old['address']))
            if item is None or digest(item['code']) != old['code_sha256']:
                raise ValueError('baseline leaf missing or changed')
        report['baseline_leaves_promoted'] = sum(
            old['tier'] != 'llvm' and current[old['image'], old['address']]['tier'] == 'llvm'
            for old in previous
        )
        report['unicorn_integration_probe'] = compatibility_probe()
        report['differential'] = compare_leaves(leaves, out, args.inputs, args.emit_aot)
        if report['differential']['mismatches']:
            raise RuntimeError('differential mismatch')
        report['status'] = 'passed'
        print(report['differential']['matches'])
    except Exception as error:
        report.update(status='failed', error=str(error))
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            report['compiler_or_oracle_stderr'] = error.stderr.decode(errors='replace')[-4000:]
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
