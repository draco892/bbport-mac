#!/usr/bin/env python3
"""Differential GPR/status-flag execution using the common 416-byte CPU state."""
import argparse
import datetime
import gzip
import hashlib
import json
import mmap
import platform
import random
import subprocess
from pathlib import Path

from cpu_state import (STATE, OFFSETS, ABI_VERSION, RFLAGS_INDEX, STATUS_INDEX,
                       XMM_INDEX, c_layout_checks)
from gpr_lift import ARITHMETIC_FLAGS, DECLARATIONS, ROTATE, SHIFT, decode, defined_flags, lift

ROOT = Path(__file__).resolve().parent
SEED = 0xbbf1a6
MASK64 = (1 << 64) - 1


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def condition(cc, flags):
    c, p, z, s, o = [bool(flags & bit) for bit in (1, 4, 64, 128, 2048)]
    return (o, not o, c, not c, z, not z, c or z, not (c or z),
            s, not s, p, not p, s != o, s == o, z or s != o, not z and s == o)[cc]


def model(code, record):
    """Independent integer math: signed ranges/nibble carries, not LLVM formulas."""
    state = list(STATE.unpack(record))
    flags = state[RFLAGS_INDEX]
    for insn in decode(code):
        w, op = insn.width, insn.op
        mask, sign = (1 << w) - 1, 1 << (w - 1)
        a, b = state[insn.dst] & mask, state[insn.src] & mask
        if insn.immediate is not None:
            b = insn.immediate & mask
        signed = lambda value: value - (1 << w) if value & sign else value
        if op == 'mov': result = b
        elif op in ('movsx', 'movzx'):
            source = 1 << insn.source_width
            result = b & (source - 1)
            if op == 'movsx' and result >= source // 2:
                result = (result - source) & mask
        elif op == 'cmov': result = b if condition(insn.condition, flags) else a
        elif op in SHIFT.values():
            b &= w - 1
            result = a
            if b:
                for _ in range(b):
                    if op in ('rol', 'shl'):
                        cf = bool(result & sign)
                        result = ((result << 1) | (cf and op == 'rol')) & mask
                    else:
                        cf = bool(result & 1)
                        top = (cf and op == 'ror') or (op == 'sar' and bool(result & sign))
                        result = (result >> 1) | (sign if top else 0)
                of = b == 1 and {
                    'rol': bool(result & sign) != cf,
                    'ror': bool(result & sign) != bool(result & (sign >> 1)),
                    'shl': bool(result & sign) != cf,
                    'shr': bool(a & sign),
                    'sar': False,
                }[op]
                flags = (flags & ~0x801) | int(cf) | (int(of) << 11)
                if op not in ROTATE:
                    flags &= ~0xd4
                    flags |= (int((result & 255).bit_count() % 2 == 0) << 2 |
                              int(result == 0) << 6 | int(bool(result & sign)) << 7)
        else:
            previous_cf = flags & 1
            if op in ('inc', 'dec'): b = 1
            carry_in = previous_cf if op in ('adc', 'sbb') else 0
            subtract = op in ('sub', 'sbb', 'cmp', 'dec')
            if op in ('and', 'or', 'xor', 'test'):
                result = {'and': a & b, 'or': a | b, 'xor': a ^ b, 'test': a & b}[op]
                cf = of = af = False
            else:
                total = a - b - carry_in if subtract else a + b + carry_in
                signed_total = signed(a) - signed(b) - carry_in if subtract else signed(a) + signed(b) + carry_in
                result = total & mask
                cf = total < 0 if subtract else total > mask
                of = not -sign <= signed_total < sign
                nibble_total = (a & 15) - (b & 15) - carry_in if subtract else (a & 15) + (b & 15) + carry_in
                af = nibble_total < 0 if subtract else nibble_total > 15
                if op in ('inc', 'dec'): cf = bool(previous_cf)
            new = int(cf) | (int((result & 255).bit_count() % 2 == 0) << 2)
            new |= int(af) << 4 | int(result == 0) << 6 | int(bool(result & sign)) << 7 | int(of) << 11
            flags = (flags & ~ARITHMETIC_FLAGS) | new
        if op not in ('cmp', 'test'):
            state[insn.dst] = (state[insn.dst] & ~mask) | result if w < 32 else result
    state[RFLAGS_INDEX], state[STATUS_INDEX] = flags, 0
    return STATE.pack(*state)


def make_state(index, gpr, flags):
    xmm = [((0x1020304050607081 * (i + 1)) ^ (index * 0x100000001)) & MASK64 for i in range(32)]
    # Non-arithmetic bits are opaque preserved state. The oracle installs only
    # the six arithmetic bits in hardware; it never enables DF/TF/privileged modes.
    rflags = 0xa500000000000202 | flags
    return STATE.pack(*gpr, *xmm, 0x200000000 + index * 16, rflags,
                      (0x1f80, 0xffc0, 0xa5a55a5a)[index % 3], 0xa5a5a5a5, 0x51a7e001cafef00d)


def corpus(random_count):
    edge = [0, 1, 2, 15, 16, 127, 128, 255, 256, 0x7fffffff, 0x80000000,
            0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, MASK64]
    records, descriptions = [], []

    def append(gpr, flags, description):
        index = len(records)
        records.append(make_state(index, gpr, flags))
        descriptions.append(description)
        return index

    for a in edge:
        for b in edge:
            for flags in (0, 1, 0x804, ARITHMETIC_FLAGS):
                append([a if r % 2 == 0 else b for r in range(16)], flags,
                       {'a': hex(a), 'b': hex(b), 'initial_arithmetic_flags': hex(flags)})
    for a in range(256):
        for b in (0, 1, 15, 16, 127, 128, 255):
            for flags in (0, 1):
                append([a if r % 2 == 0 else b for r in range(16)], flags,
                       {'low_byte_pair': [a, b], 'carry': flags})
    for bits in range(64):
        flags = sum(((bits >> i) & 1) * bit for i, bit in enumerate((1, 4, 16, 64, 128, 2048)))
        append([(0x1234567800000001 * (r + 1)) & MASK64 for r in range(16)], flags,
               {'all_initial_flag_combinations': bits})
    rng = random.Random(SEED)
    for _ in range(random_count):
        append([rng.getrandbits(64) for _ in range(16)], rng.getrandbits(12) & ARITHMETIC_FLAGS,
               {'seeded_random': True})
    # Independently specified complete outcomes, with non-target fields retained.
    known = []
    literals = [
        ('add', 64, MASK64, 1, 0, 0, 0x55),
        ('add', 64, (1 << 63) - 1, 1, 0, 1 << 63, 0x894),
        ('add', 64, 1 << 63, MASK64, 0, (1 << 63) - 1, 0x805),
        ('adc', 64, MASK64, 0, 1, 0, 0x55),
        ('adc', 64, (1 << 63) - 1, 0, 1, 1 << 63, 0x894),
        ('sub', 64, 0, 1, 0, MASK64, 0x95),
        ('sub', 64, 1 << 63, 1, 0, (1 << 63) - 1, 0x814),
        ('sbb', 64, 0, MASK64, 1, 0, 0x55),
        ('sbb', 64, 1 << 63, (1 << 63) - 1, 1, 0, 0x854),
        ('inc', 64, (1 << 63) - 1, 0, 1, 1 << 63, 0x895),
        ('dec', 64, 1 << 63, 0, 1, (1 << 63) - 1, 0x815),
        ('and', 64, 0, MASK64, ARITHMETIC_FLAGS, 0, 0x44),
        ('or', 64, 0, 1, ARITHMETIC_FLAGS, 1, 0),
        ('xor', 64, MASK64, MASK64, ARITHMETIC_FLAGS, 0, 0x44),
        ('cmp', 64, 42, 42, ARITHMETIC_FLAGS, None, 0x44),
        ('test', 64, 0, MASK64, ARITHMETIC_FLAGS, None, 0x44),
        ('add', 32, 0xdeadbeefffffffff, 1, 0, 0, 0x55),
        ('sub', 32, 0xdeadbeef80000000, 1, 0, 0x7fffffff, 0x814),
        ('cmp', 32, 0xdeadbeef00000000, 1, 0, None, 0x95),
        ('mov', 32, MASK64, 0x12345678ffffffff, ARITHMETIC_FLAGS, 0xffffffff, ARITHMETIC_FLAGS),
        ('cmov4', 32, 0xffffffff87654321, 0xfeedbeef01234567, 1, 0x87654321, 1),
        ('cmov4', 32, 0xffffffff87654321, 0xfeedbeef01234567, 0x40, 0x01234567, 0x40),
    ]
    for op, width, a, b, flags, result, expected_flags in literals:
        name = f'{op}{width}_r0' if op in ('inc', 'dec') else f'{op}{width}_r0_r5'
        gpr = [(0x123456789abcdef * (r + 1)) & MASK64 for r in range(16)]
        gpr[0], gpr[5] = a, b
        index = append(gpr, flags, {'known_answer': name})
        expected = list(STATE.unpack(records[index]))
        if result is not None: expected[0] = result
        expected[RFLAGS_INDEX] = (expected[RFLAGS_INDEX] & ~ARITHMETIC_FLAGS) | expected_flags
        expected[STATUS_INDEX] = 0
        known.append((index, name, STATE.pack(*expected)))
    return records, descriptions, known


def oracle_assembly(codes):
    names = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
    saved = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')
    lines = ['.text']
    for name, code in codes.items():
        decode(code)
        lines += [f'.globl _{name}', f'_{name}:'] + [f'pushq %{r}' for r in saved]
        # Host scratch XMM registers belong to the oracle wrapper, not the guest
        # SIMD state. No globals or guest-stack memory are required.
        lines += ['movq %rdi, %xmm15', 'movq %rsp, %xmm14',
                  f'movq {OFFSETS["rflags"]}(%rdi), %rax', 'andq $0x8d5, %rax',
                  'orq $0x202, %rax', 'pushq %rax', 'popfq']
        lines += [f'movq {i * 8}(%rdi), %{r}' for i, r in enumerate(names) if r != 'rdi']
        lines += ['movq 56(%rdi), %rdi', '.byte ' + ','.join(str(byte) for byte in code[:-1]),
                  'movq %rax, %xmm12', 'movq %rsp, %xmm13', 'movq %xmm14, %rsp',
                  'movq %xmm15, %rax']
        lines += [f'movq %{r}, {i * 8}(%rax)' for i, r in enumerate(names) if r not in ('rax', 'rsp')]
        lines += ['movq %xmm12, %rdx', 'movq %rdx, 0(%rax)',
                  'movq %xmm13, %rdx', 'movq %rdx, 32(%rax)', 'pushfq', 'popq %rdx',
                  f'andq ${defined_flags(code)}, %rdx',
                  f'movq {OFFSETS["rflags"]}(%rax), %rcx',
                  f'andq ${-1 ^ ARITHMETIC_FLAGS}, %rcx', 'orq %rdx, %rcx',
                  f'movq %rcx, {OFFSETS["rflags"]}(%rax)',
                  f'movl $0, {OFFSETS["status"]}(%rax)']
        lines += [f'popq %{r}' for r in reversed(saved)] + ['ret']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-gpr')
    parser.add_argument('--random-count', type=int, default=1024)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.random_count < 0: parser.error('--random-count must be nonnegative')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'synthetic 32/64-bit GPR and arithmetic flags; no game execution',
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'commands': [], 'steps': []}

    def save(): report_path.write_text(json.dumps(report, indent=2) + '\n')

    def command(label, argv, inputs=None):
        argv = [str(v) for v in argv]
        report['commands'].append(argv)
        save()
        print(label, flush=True)
        output = out / (label + ('.bin' if inputs is not None else '.stdout.log'))
        with output.open('wb') as stream:
            result = subprocess.run(argv, input=inputs, stdout=stream, stderr=subprocess.PIPE, timeout=300)
        (out / (label + '.stderr.log')).write_bytes(result.stderr)
        report['steps'].append({'name': label, 'exit_code': result.returncode})
        save()
        if result.returncode:
            raise RuntimeError(f'{label}: exit {result.returncode}; inspect {label}.stderr.log')
        return output

    save()
    try:
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('run with native ARM64 Python on Apple Silicon')
        fixtures = json.loads((ROOT / 'gpr_fixtures.json').read_text())
        codes = {name: bytes.fromhex(code) for name, code in fixtures.items()}
        names = list(codes)
        (out / 'gpr.ll').write_text(DECLARATIONS + '\n\n'.join(lift(code, name) for name, code in codes.items()))
        (out / 'original.s').write_text(oracle_assembly(codes))
        (out / 'cpu_state_layout.h').write_text(c_layout_checks())
        (out / 'gpr_functions.h').write_text('#define GPR_FUNCTIONS(X) \\\n' + ' \\\n'.join(f' X({name})' for name in names) + '\n')
        records, descriptions, known = corpus(args.random_count)
        inputs = b''.join(records)
        (out / 'inputs.bin').write_bytes(inputs)
        (out / 'inputs.json').write_text(json.dumps(descriptions, indent=2) + '\n')
        (out / 'known-answers.json').write_text(json.dumps([
            {'input_index': index, 'function': name, 'expected': expected.hex()} for index, name, expected in known], indent=2) + '\n')
        outputs = {}
        for label, arch in (('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')):
            argv = ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-I', ROOT, '-I', out, ROOT / 'gpr_harness.c',
                    out / ('original.s' if label.startswith('original') else 'gpr.ll')]
            exe = out / label
            command(label + '-build', argv + ['-o', exe])
            outputs[label] = command(label + '-run', ['/usr/bin/arch', '-' + arch, exe], inputs)
            if args.sanitize and arch == 'arm64':
                exe = out / 'aot-arm64-ubsan'
                command('aot-arm64-ubsan-build', argv + ['-fsanitize=undefined', '-fno-sanitize-recover=all', '-o', exe])
                outputs['aot-arm64-ubsan'] = command('aot-arm64-ubsan-run', ['/usr/bin/arch', '-arm64', exe], inputs)
        expected_size = len(records) * len(names) * STATE.size
        for label, path in outputs.items():
            if path.stat().st_size != expected_size: raise RuntimeError(f'{label}: incomplete output')
            with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                for index, name, expected in known:
                    position = (index * len(names) + names.index(name)) * STATE.size
                    if data[position:position + STATE.size] != expected:
                        (out / 'known-mismatch.json').write_text(json.dumps(dict(backend=label, function=name,
                            input_index=index, expected=expected.hex(), actual=data[position:position + STATE.size].hex()), indent=2))
                        raise RuntimeError(f'{label}: known answer mismatch; see known-mismatch.json')
        reference = outputs['original-x86_64']
        for label, path in outputs.items():
            with reference.open('rb') as left, path.open('rb') as right:
                offset = 0
                while a := left.read(1024 * 1024):
                    b = right.read(len(a))
                    if a != b:
                        first = offset + next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
                        index, f = divmod(first // STATE.size, len(names))
                        report['mismatch'] = dict(backend=label, input_index=index, input=descriptions[index], function=names[f])
                        raise RuntimeError(f'{label}: differential mismatch at {names[f]}, input {index}')
                    offset += len(a)
        independent = 0
        with reference.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            indices = sorted(set(range(min(64, len(records)))) | set(range(0, len(records), 17)) |
                             {i for i, _, _ in known})
            for index in indices:
                for f, name in enumerate(names):
                    expected = model(codes[name], records[index])
                    position = (index * len(names) + f) * STATE.size
                    if data[position:position + STATE.size] != expected:
                        raise RuntimeError(f'independent model mismatch at {name}, input {index}')
                    independent += 1
        result_hashes = {name: sha(path) for name, path in outputs.items()}
        assert len(set(result_hashes.values())) == 1
        # Retain identical full snapshots once, with an independently checked
        # lossless round trip before removing any raw result files.
        archive = out / ('snapshots-' + result_hashes['original-x86_64'] + '.bin.gz')
        print('archive-results', flush=True)
        with reference.open('rb') as source, gzip.open(archive, 'wb', compresslevel=1) as target:
            while chunk := source.read(4 * 1024 * 1024): target.write(chunk)
        with gzip.open(archive, 'rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != result_hashes['original-x86_64']:
                raise RuntimeError('archive round-trip mismatch; raw results retained')
        report.update(host=platform.platform(), machine=platform.machine(), cpu_state_abi=ABI_VERSION,
                      cpu_state_bytes=STATE.size, cpu_state_offsets=OFFSETS, seed=hex(SEED), fixtures=len(codes),
                      input_states=len(records), comparisons_per_aot_backend=len(records) * len(codes), mismatches=0,
                      known_answers_per_backend=len(known), independent_model_snapshots=independent, native_ubsan=args.sanitize,
                      defined_arithmetic_flag_masks={name: hex(defined_flags(code)) for name, code in codes.items()},
                      undefined_flags='Logical AF normalized to zero; not compared as architectural behavior.',
                      oracle='Original register instructions under Rosetta, inlined before restoring host RSP; no guest RET execution.',
                      source_sha256={str((ROOT / name).relative_to(ROOT.parent)): sha(ROOT / name)
                          for name in ('gpr_lift.py', 'gpr_harness.c', 'run_gpr.py', 'gpr_fixtures.json', 'cpu_state.py', 'cpu_state.h')},
                      inputs_sha256=sha(out / 'inputs.bin'), results_sha256=result_hashes,
                      result_archive=dict(path=archive.name, sha256=sha(archive), compression='gzip',
                                          uncompressed_sha256=result_hashes['original-x86_64'], uncompressed_bytes=expected_size))
        compiler = command('compiler', ['xcrun', 'clang', '--version'])
        report['compiler'] = compiler.read_text()
        report['status'] = 'passed'
        save()
        for path in outputs.values(): path.unlink()
        print(f'PASS: {len(records) * len(codes)} snapshots per AOT backend, 0 mismatches; {report_path}', flush=True)
    except Exception as error:
        report.update(status='failed', error=str(error))
        save()
        raise


if __name__ == '__main__': main()
