#!/usr/bin/env python3
"""Differential register-only SSE/SSE2 correctness on original x86 and ARM64 AOT."""
import argparse
import datetime
import hashlib
import json
import mmap
import platform
import random
import struct
import subprocess
from pathlib import Path

from simd_lift import FP_IDS, decode, declarations, lift
from cpu_state import (ABI_VERSION, STATE, XMM_INDEX, MXCSR_INDEX, STATUS_INDEX,
                       MXCSR_OFFSET, STATUS_OFFSET, OFFSETS, xmm_offset,
                       c_layout_checks, expand_legacy)

ROOT = Path(__file__).resolve().parent
VENDOR = ROOT.parent / 'third_party/softfloat'
LEGACY_STATE = struct.Struct('<4QIIQ')
SEED = 0xbb109


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def softfloat_inputs(vendor):
    return ['-DSOFTFLOAT_FAST_INT64', '-DINLINE_LEVEL=5', '-DSOFTFLOAT_FAST_DIV32TO16',
            '-DSOFTFLOAT_FAST_DIV64TO32', '-DTHREAD_LOCAL=_Thread_local',
            '-I', VENDOR / 'build/Linux-x86_64-GCC',
            '-I', VENDOR / 'source/8086-SSE', '-I', VENDOR / 'source/include',
            ROOT / 'simd_fp.c', *(VENDOR / source for source in vendor['sources'])]


def load_fixtures():
    fixtures = json.loads((ROOT / 'simd_fixtures.json').read_text())
    extended = json.loads((ROOT / 'simd_register_fixtures.json').read_text())
    if fixtures.keys() & extended.keys():
        raise ValueError('duplicate SIMD fixture names')
    return {**fixtures, **extended}


def corpus(random_count):
    edge32 = [0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x807fffff,
              0x00800000, 0x80800000, 0x00800001, 0x3f000000, 0x3f800000,
              0xbf800000, 0x40000000, 0x40400000, 0x33800000, 0x3f800001, 0x3f7fffff,
              0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000,
              0x7fc00001, 0xffc00002, 0x7f800001, 0xff800003]
    edge64 = [0, 0x8000000000000000, 1, 0x8000000000000001,
              0x000fffffffffffff, 0x800fffffffffffff, 0x0010000000000000,
              0x8010000000000000, 0x0010000000000001, 0x3fe0000000000000,
              0x3ff0000000000000, 0xbff0000000000000, 0x4000000000000000,
              0x4008000000000000, 0x3ca0000000000000, 0x3ff0000000000001, 0x3fefffffffffffff,
              0x7fefffffffffffff, 0xffefffffffffffff, 0x7ff0000000000000,
              0xfff0000000000000, 0x7ff8000000000001, 0xfff8000000000002,
              0x7ff0000000000001, 0xfff0000000000003]
    base = []
    for width, edge in ((32, edge32), (64, edge64)):
        for i, a in enumerate(edge):
            for j, b in enumerate(edge):
                if width == 32:
                    av = [a, edge[(i + 1) % len(edge)], a ^ 0x80000000, edge[(j + 7) % len(edge)]]
                    bv = [b, edge[(j + 3) % len(edge)], b ^ 0x80000000, edge[(i + 9) % len(edge)]]
                    words = struct.unpack('<4Q', struct.pack('<8I', *av, *bv))
                else:
                    words = (a, edge[(i + 1) % len(edge)], b, edge[(j + 3) % len(edge)])
                base.append((words, None))
    rng = random.Random(SEED)
    base.extend((tuple(rng.getrandbits(64) for _ in range(4)), None)
                for _ in range(random_count))
    # Cross every signed/unsigned saturation boundary, with distinct lanes so
    # packing order and high-half interleaves cannot pass as broadcast copies.
    for width in (8, 16, 32):
        mask = (1 << width) - 1
        edge = [0, 1, 2, (1 << (width - 1)) - 2, (1 << (width - 1)) - 1,
                1 << (width - 1), (1 << (width - 1)) + 1, mask - 1, mask]
        if width > 8:
            edge += [127, 128, 255, 256]
        if width == 32:
            edge += [32767, 32768, 65535, 65536]
        for i, a in enumerate(edge):
            for j, b in enumerate(edge):
                vectors = [sum((value if lane == 0 else edge[(offset + lane) % len(edge)])
                               << (lane * width) for lane in range(128 // width))
                           for value, offset in ((a, j), (b, i))]
                base.append(((vectors[0] & ((1 << 64) - 1), vectors[0] >> 64,
                              vectors[1] & ((1 << 64) - 1), vectors[1] >> 64), None))
    # Known results do not come from either the lifter or SoftFloat. The other
    # scalar destination lanes contain distinct, observable sentinel bits.
    for width, one, two, four, half_ulp, normal, largest, inf, sign, qnan in (
        (32, 0x3f800000, 0x40000000, 0x40800000, 0x33800000, 0x00800000,
         0x7f7fffff, 0x7f800000, 0x80000000, 0xffc00000),
        (64, 0x3ff0000000000000, 0x4000000000000000, 0x4010000000000000,
         0x3ca0000000000000, 0x0010000000000000, 0x7fefffffffffffff,
         0x7ff0000000000000, 0x8000000000000000, 0xfff8000000000000),
    ):
        suffix = 'ss' if width == 32 else 'sd'
        known = [
            ('add', one, half_ulp, [one, one, one + 1, one], 32),
            ('add', one, one | sign, [0, sign, 0, 0], 0),
            ('div', one, 0, [inf] * 4, 4),
            ('div', 0, 0, [qnan] * 4, 1),
            ('div', normal, two, [normal >> 1] * 4, 0),
            ('div', 1, two, [0, 0, 1, 0], 0x32),
            ('mul', largest, two, [inf, largest, inf, largest], 0x28),
            ('sqrt', one, four, [two] * 4, 0),
            ('sqrt', one, one | sign, [qnan] * 4, 1),
            ('div', 1, 0, [inf] * 4, 4),
            ('sqrt', one, sign | 1, [qnan] * 4, 1),
            ('div', normal, one + 1, [normal - 1, normal - 1, normal, normal - 1], 0x30),
            ('div', normal + 1, one + 1, [normal] * 4, 0),
            ('mul', normal, one - 1, [normal, normal - 1, normal, normal - 1], 0x30),
            ('add', qnan | 1, inf | 3, [qnan | 1] * 4, 1),
        ]
        for op, a, b, results, flags in known:
            if width == 32:
                words = (a | (0x7f800001 << 32), 0x123456789abcdef0,
                         b | (0xff800002 << 32), 0xfedcba9876543210)
            else:
                words = (a, 0x7ff0000000000001, b, 0xfff0000000000002)
            known_case = {'function': op + suffix, 'width': width,
                          'results': results, 'flags': flags, 'normal': normal, 'sign': sign}
            if a == 1 and op == 'div':
                known_case['daz_result'] = qnan if b == 0 else 0
                known_case['daz_flags'] = 1 if b == 0 else 0
            if op == 'sqrt' and b == (sign | 1):
                known_case['daz_result'], known_case['daz_flags'] = sign, 0
            if (op == 'div' and a == normal and b == one + 1) or (op == 'mul' and a == normal and b == one - 1):
                known_case['ftz_result'] = 0
            base.append((words, known_case))
    records, descriptions, known_records = [], [], []
    for base_id, (words, known) in enumerate(base):
        for rounding in range(4):
            for denorm in (0, 0x40, 0x8000, 0x8040):
                for sticky in (0, 0x3f):
                    mxcsr = 0x1f80 | (rounding << 13) | denorm | sticky
                    state = (*words, mxcsr, 0xa5a5a5a5, 0x51a7e001cafef00d)
                    index = len(records)
                    records.append(LEGACY_STATE.pack(*state))
                    descriptions.append({'base_id': base_id, 'xmm_words_hex': [f'{x:016x}' for x in words],
                                         'mxcsr': hex(mxcsr)})
                    if known:
                        expected = list(state)
                        mask = (1 << known['width']) - 1
                        result, flags = known['results'][rounding], known['flags']
                        if denorm & 0x40 and 'daz_result' in known:
                            result, flags = known['daz_result'], known['daz_flags']
                        absolute = result & (known['sign'] - 1)
                        if denorm & 0x8000 and 0 < absolute < known['normal']:
                            result &= known['sign']
                            flags |= 0x30
                        if denorm & 0x8000 and 'ftz_result' in known:
                            result = known['ftz_result']
                        expected[0] = (words[0] & ~mask) | result
                        expected[4] |= flags
                        expected[5] = 0
                        known_records.append((index, known['function'], LEGACY_STATE.pack(*expected)))
    # Literal integer answers are separate from the executable Python model.
    # Include all controls to prove these instructions leave MXCSR unchanged.
    integer_known = [
        ('sadd_sat8', 'b', [127, -128, 126, -127] * 4, [1, -1, 1, -1] * 4,
         [127, -128, 127, -128] * 4),
        ('uadd_sat8', 'B', [255, 254, 0, 128] * 4, [1, 1, 255, 128] * 4,
         [255, 255, 255, 255] * 4),
        ('ssub_sat16', 'h', [-32768, 32767, -1, 1] * 2, [1, -1, -1, 1] * 2,
         [-32768, 32767, 0, 0] * 2),
        ('usub_sat16', 'H', [0, 65535, 1, 32768] * 2, [1, 65535, 2, 1] * 2,
         [0, 0, 0, 32767] * 2),
        ('pack_unsigned16', 'h', [-32768, -1, 0, 127, 128, 255, 256, 32767],
         [256, 255, 128, 127, 0, -1, -32768, 1],
         [0, 0, 0, 127, 128, 255, 255, 255, 255, 255, 128, 127, 0, 0, 0, 1]),
        ('pack_signed32', 'i', [-32769, -32768, 32767, 32768],
         [-2147483648, 2147483647, -1, 0],
         [-32768, -32768, 32767, 32767, -32768, 32767, -1, 0]),
        ('madd16', 'h', [-32768] * 8, [-32768] * 8, [-2147483648] * 4),
        ('mulhi_signed16', 'h', [-32768, -1, 32767, 256] * 2,
         [32767, 1, 32767, 256] * 2, [-16384, -1, 16383, 1] * 2),
        ('mulhi_unsigned16', 'H', [65535, 32768, 1, 256] * 2,
         [65535, 32768, 65535, 256] * 2, [65534, 16384, 0, 1] * 2),
        ('unpackhi32', 'I', [1, 2, 3, 4], [5, 6, 7, 8], [3, 7, 4, 8]),
    ]
    for name, fmt, a, b, expected in integer_known:
        words = struct.unpack('<4Q', struct.pack('<' + fmt * len(a), *a) +
                              struct.pack('<' + fmt * len(b), *b))
        output_fmt = {'pack_unsigned16': 'B', 'pack_signed32': 'h', 'madd16': 'i'}.get(name, fmt)
        output_words = struct.unpack('<2Q', struct.pack('<' + output_fmt * len(expected), *expected))
        for rounding in range(4):
            for denorm in (0, 0x40, 0x8000, 0x8040):
                for sticky in (0, 0x3f):
                    mxcsr = 0x1f80 | (rounding << 13) | denorm | sticky
                    index = len(records)
                    records.append(LEGACY_STATE.pack(*words, mxcsr, 0xa5a5a5a5, 0x51a7e001cafef00d))
                    descriptions.append({'integer_known_answer': name,
                                         'xmm_words_hex': [f'{x:016x}' for x in words], 'mxcsr': hex(mxcsr)})
                    known_records.append((index, name, LEGACY_STATE.pack(*output_words, *words[2:],
                                                                 mxcsr, 0, 0x51a7e001cafef00d)))
    records = [expand_legacy(record, index) for index, record in enumerate(records)]
    expanded_known = []
    for index, name, expected in known_records:
        old = LEGACY_STATE.unpack(expected)
        full = list(STATE.unpack(records[index]))
        full[XMM_INDEX:XMM_INDEX + 4] = old[:4]
        full[MXCSR_INDEX:MXCSR_INDEX + 2] = old[4:6]
        expanded_known.append((index, name, STATE.pack(*full)))
    # Repeat each explicit answer with the exact same operands in XMM8/XMM15.
    # Other registers (including XMM0/XMM1) must remain unchanged.
    for index, name, expected in expanded_known.copy():
        original_input = list(STATE.unpack(records[index]))
        high_input = original_input.copy()
        high_expected = list(STATE.unpack(expected))
        for old, new in ((0, 8), (1, 15)):
            high_input[XMM_INDEX + 2 * new:XMM_INDEX + 2 * new + 2] = original_input[XMM_INDEX + 2 * old:XMM_INDEX + 2 * old + 2]
        result = high_input.copy()
        for old, new in ((0, 8), (1, 15)):
            result[XMM_INDEX + 2 * new:XMM_INDEX + 2 * new + 2] = high_expected[XMM_INDEX + 2 * old:XMM_INDEX + 2 * old + 2]
        result[MXCSR_INDEX:MXCSR_INDEX + 2] = high_expected[MXCSR_INDEX:MXCSR_INDEX + 2]
        high_index = len(records)
        records.append(STATE.pack(*high_input))
        descriptions.append({**descriptions[index], 'high_register_copy_of': index})
        expanded_known.append((high_index, name + '_xmm8_15', STATE.pack(*result)))
    return records, descriptions, expanded_known


def integer_model(code, record):
    state = list(STATE.unpack(record))
    regs = [state[XMM_INDEX + 2 * r] | (state[XMM_INDEX + 2 * r + 1] << 64) for r in range(16)]
    for insn in decode(code):
        a, b = regs[insn.dst], regs[insn.src]
        if insn.op in FP_IDS:
            return None
        if insn.op == 'mov':
            out = b
        elif insn.op in ('unpacklo', 'unpackhi', 'pack_signed', 'pack_unsigned', 'madd'):
            w = insn.width
            mask = (1 << w) - 1
            lanes = lambda value: [(value >> shift) & mask for shift in range(0, 128, w)]
            signed = lambda value: value - (1 << w) if value & (1 << (w - 1)) else value
            aa, bb = lanes(a), lanes(b)
            if insn.op.startswith('unpack'):
                half = len(aa) // 2
                start = 0 if insn.op == 'unpacklo' else half
                values = [v for pair in zip(aa[start:start + half], bb[start:start + half]) for v in pair]
            elif insn.op == 'madd':
                products = [signed(x) * signed(y) for x, y in zip(aa, bb)]
                values = [products[i] + products[i + 1] for i in range(0, len(products), 2)]
                w = 32
            else:
                values = [signed(x) for x in aa + bb]
                w //= 2
                low, high = (-(1 << (w - 1)), (1 << (w - 1)) - 1) if insn.op == 'pack_signed' else (0, (1 << w) - 1)
                values = [min(high, max(low, x)) for x in values]
            out = sum((value & ((1 << w) - 1)) << (lane * w) for lane, value in enumerate(values))
        elif insn.width == 128:
            out = {'and': lambda: a & b, 'andnot': lambda: ~a & b,
                   'or': lambda: a | b, 'xor': lambda: a ^ b}[insn.op]()
        else:
            w, out = insn.width, 0
            mask = (1 << w) - 1
            signed = lambda x: x - (1 << w) if x >> (w - 1) else x
            for lane in range(128 // w):
                aa, bb = (a >> (lane * w)) & mask, (b >> (lane * w)) & mask
                if insn.op == 'shuffle':
                    value = b >> (((insn.immediate >> (lane * 2)) & 3) * w)
                elif insn.op == 'add': value = aa + bb
                elif insn.op == 'sub': value = aa - bb
                elif insn.op in ('sadd_sat', 'ssub_sat', 'uadd_sat', 'usub_sat'):
                    is_signed = insn.op.startswith('s')
                    x, y = (signed(aa), signed(bb)) if is_signed else (aa, bb)
                    value = x + y if 'add' in insn.op else x - y
                    low, high = (-(1 << (w - 1)), (1 << (w - 1)) - 1) if is_signed else (0, mask)
                    value = max(low, min(high, value))
                elif insn.op == 'mullo': value = aa * bb
                elif insn.op == 'mulhi_signed': value = (signed(aa) * signed(bb)) >> w
                elif insn.op == 'mulhi_unsigned': value = (aa * bb) >> w
                elif insn.op == 'eq': value = -int(aa == bb)
                elif insn.op == 'gt': value = -int(signed(aa) > signed(bb))
                elif insn.op == 'shl': value = aa << insn.immediate
                elif insn.op == 'lshr': value = aa >> insn.immediate
                elif insn.op == 'ashr': value = signed(aa) >> insn.immediate
                else: raise AssertionError(insn)
                out |= (value & mask) << (lane * w)
        regs[insn.dst] = out & ((1 << 128) - 1)
    state[XMM_INDEX:XMM_INDEX + 32] = [word for value in regs
                                     for word in (value & ((1 << 64) - 1), value >> 64)]
    state[STATUS_INDEX] = 0
    return STATE.pack(*state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-simd')
    parser.add_argument('--random-count', type=int, default=256)
    parser.add_argument('--sanitize', action='store_true', help='also run native ARM64 with UndefinedBehaviorSanitizer')
    args = parser.parse_args()
    if args.random_count < 0:
        parser.error('--random-count must be nonnegative')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'synthetic register-only SSE/SSE2; no game execution',
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'commands': [], 'steps': []}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    def command(label, argv, input_bytes=None, binary_output=False):
        argv = [str(x) for x in argv]
        report['commands'].append(argv)
        save()
        print(label, flush=True)
        output = out / f'{label}.bin' if binary_output else out / f'{label}.stdout.log'
        with output.open('wb') as stream:
            result = subprocess.run(argv, input=input_bytes, stdout=stream,
                                    stderr=subprocess.PIPE, timeout=300)
        (out / f'{label}.stderr.log').write_bytes(result.stderr)
        report['steps'].append({'name': label, 'exit_code': result.returncode})
        save()
        if result.returncode:
            raise RuntimeError(f'{label}: exit {result.returncode}; see {label}.stderr.log')
        return output

    save()
    try:
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('run with native ARM64 Python on Apple Silicon')
        vendor = json.loads((VENDOR / 'manifest.json').read_text())
        for relative, expected in vendor['files_sha256'].items():
            if sha(VENDOR / relative) != expected:
                raise RuntimeError(f'vendored SoftFloat hash mismatch: {relative}')
        fixtures = load_fixtures()
        codes = {name: bytes.fromhex(code) for name, code in fixtures.items()}
        names = list(codes)
        (out / 'simd.ll').write_text(declarations() + '\n\n'.join(lift(c, n) for n, c in codes.items()) + '\n')
        macro = '#define SIMD_FUNCTIONS(X) \\\n' + ' \\\n'.join(f'    X({n})' for n in names) + '\n'
        (out / 'simd_functions.h').write_text(macro)
        (out / 'cpu_state_layout.h').write_text(c_layout_checks())
        assembly = ['.text']
        for name, code in codes.items():
            assembly += [f'.globl _{name}', f'_{name}:', 'subq $8, %rsp', 'stmxcsr (%rsp)',
                         f'ldmxcsr {MXCSR_OFFSET}(%rdi)']
            assembly += [f'movdqu {xmm_offset(r)}(%rdi), %xmm{r}' for r in range(16)]
            # Only the six arithmetic status flags are observed here. No DF,
            # trap/privileged modes or general flag-changing guest code.
            assembly += [f'pushq {OFFSETS["rflags"]}(%rdi)', 'popfq', f'call Loriginal_{name}']
            assembly += [f'movdqu %xmm{r}, {xmm_offset(r)}(%rdi)' for r in range(16)]
            assembly += [f'stmxcsr {MXCSR_OFFSET}(%rdi)', 'pushfq', 'popq %rax',
                         f'xorq {OFFSETS["rflags"]}(%rdi), %rax', 'testq $0x8d5, %rax',
                         f'jnz Lflags_failure_{name}', 'ldmxcsr (%rsp)', 'addq $8, %rsp',
                         f'movl $0, {STATUS_OFFSET}(%rdi)', 'ret',
                         f'Lflags_failure_{name}:', 'ud2', f'Loriginal_{name}:',
                         '.byte ' + ','.join(str(x) for x in code)]
        (out / 'original.s').write_text('\n'.join(assembly) + '\n')
        records, descriptions, known = corpus(args.random_count)
        inputs = b''.join(records)
        (out / 'inputs.bin').write_bytes(inputs)
        (out / 'inputs.json').write_text(json.dumps(descriptions, indent=2) + '\n')
        (out / 'known-answers.json').write_text(json.dumps([
            {'input_index': i, 'function': name, 'expected_snapshot_hex': expected.hex()}
            for i, name, expected in known], indent=2) + '\n')
        outputs = {}
        for label, arch in [('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')]:
            argv = ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-I', out, '-I', ROOT, ROOT / 'simd_harness.c']
            if label.startswith('original'):
                argv += ['-DORIGINAL', out / 'original.s']
            else:
                argv += [*softfloat_inputs(vendor), out / 'simd.ll']
            exe = out / label
            command(label + '-build', argv + ['-o', exe])
            outputs[label] = command(label + '-run', ['/usr/bin/arch', '-' + arch, exe],
                                     input_bytes=inputs, binary_output=True)
            if label.startswith('aot'):
                command(label + '-negative', ['/usr/bin/arch', '-' + arch, exe, '--negative'])
            if args.sanitize and arch == 'arm64':
                sanitized = out / 'aot-arm64-ubsan'
                command('aot-arm64-ubsan-build', argv + ['-fsanitize=undefined',
                        '-fno-sanitize-recover=all', '-o', sanitized])
                outputs['aot-arm64-ubsan'] = command('aot-arm64-ubsan-run',
                        ['/usr/bin/arch', '-arm64', sanitized], input_bytes=inputs, binary_output=True)
        expected_size = len(records) * len(names) * STATE.size
        for label, path in outputs.items():
            if path.stat().st_size != expected_size:
                raise RuntimeError(f'{label}: incomplete snapshots')
            with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                for index, name, expected in known:
                    position = (index * len(names) + names.index(name)) * STATE.size
                    if data[position:position + STATE.size] != expected:
                        (out / 'known-mismatch.json').write_text(json.dumps({
                            'backend': label, 'input_index': index, 'input': descriptions[index],
                            'function': name, 'expected': expected.hex(),
                            'actual': data[position:position + STATE.size].hex()}, indent=2) + '\n')
                        raise RuntimeError(f'{label}: independent known answer mismatch; see known-mismatch.json')
        reference = outputs['original-x86_64']
        for label, path in outputs.items():
            with reference.open('rb') as left, path.open('rb') as right:
                offset = 0
                while True:
                    a, b = left.read(1024 * 1024), right.read(1024 * 1024)
                    if a != b:
                        first = offset + next(i for i, pair in enumerate(zip(a, b)) if pair[0] != pair[1])
                        snapshot = first // STATE.size
                        index, function = divmod(snapshot, len(names))
                        report['mismatch'] = {'backend': label, 'snapshot_index': snapshot,
                                              'input_index': index, 'input': descriptions[index],
                                              'function': names[function]}
                        raise RuntimeError(f'{label}: differential mismatch at {names[function]}, input {index}')
                    if not a: break
                    offset += len(a)
        independent_integer = 0
        with reference.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            # At least one control mode from every base case, as well as varied
            # rounding/sticky/DAZ/FTZ combinations and every first-base mode.
            indices = sorted(set(range(min(32, len(records)))) | set(range(0, len(records), 32)) |
                             set(range(0, len(records), 97)) | {len(records) - 1})
            for index in indices:
                for f, name in enumerate(names):
                    expected = integer_model(codes[name], records[index])
                    if expected is None: continue
                    position = (index * len(names) + f) * STATE.size
                    if data[position:position + STATE.size] != expected:
                        raise RuntimeError(f'independent integer model mismatch: {name}, input {index}')
                    independent_integer += 1
        report.update(host=platform.platform(), machine=platform.machine(),
                      fixtures=len(names), input_states=len(records), seed=hex(SEED),
                      cpu_state_abi=ABI_VERSION, cpu_state_bytes=STATE.size,
                      cpu_state_offsets=OFFSETS, observed_xmm_registers=list(range(16)),
                      comparisons_per_aot_backend=len(records) * len(names), mismatches=0,
                      random_base_states=args.random_count, native_ubsan=args.sanitize,
                      known_answer_snapshots_per_backend=len(known),
                      independent_integer_snapshots=independent_integer,
                      negative_checks_per_aot_backend=6 * len(names),
                      oracle='original SSE/SSE2 fixture bytes under Rosetta; development reference only',
                      rounding_modes=['nearest-even', 'toward-negative', 'toward-positive', 'toward-zero'],
                      fp_contract='masked exceptions; all four DAZ/FTZ combinations; unmasked traps/reserved bits rejected',
                      softfloat_archive_sha256=vendor['archive_sha256'],
                      source_sha256={str(p.relative_to(ROOT.parent)): sha(p) for p in
                                     [ROOT / n for n in ('simd_lift.py', 'simd_fp.c', 'simd_harness.c',
                                                        'simd_fixtures.json', 'simd_register_fixtures.json', 'run_simd.py',
                                                        'cpu_state.h', 'cpu_state.py')] +
                                     [VENDOR / 'manifest.json']},
                      inputs_sha256=sha(out / 'inputs.bin'),
                      results_sha256={name: sha(path) for name, path in outputs.items()})
        compiler = command('compiler', ['xcrun', 'clang', '--version'])
        report['compiler'] = compiler.read_text()
        report['status'] = 'passed'
        save()
        print(f'PASS: {report["comparisons_per_aot_backend"]} snapshots per AOT backend, 0 mismatches; '
              f'{len(known)} known answers; {report_path}', flush=True)
    except Exception as error:
        report.update(status='failed', error=str(error))
        save()
        raise


if __name__ == '__main__':
    main()
