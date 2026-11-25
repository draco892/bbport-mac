#!/usr/bin/env python3
"""Validate common-state guest stack, direct calls, returns and stack arguments."""
import argparse
import datetime
import gzip
import hashlib
import json
import mmap
import platform
import random
import re
import struct
import subprocess
from pathlib import Path

from cpu_state import STATE, OFFSETS, STATUS_INDEX, RFLAGS_INDEX, RIP_INDEX, c_layout_checks
from state_stack_lift import (CODE_BASE, ROOT_RETURN, DATA_BYTES, STACK_BYTES, MASK64,
                              analyze, lift, scalar_for_adjust)
from state_memory_lift import effective_address
from gpr_lift import decode as decode_gpr, ARITHMETIC_FLAGS
from run_gpr import make_state, model as gpr_model, oracle_assembly, sha

ROOT = Path(__file__).resolve().parent
DATA_BASE, STACK_BASE = 0x200000010, 0x400000010
INPUT_BYTES, OUTPUT_BYTES = 1120, 1088
SEED = 0xbb57ac


def prepare(record, entry, functions):
    state = list(STATE.unpack(record[:416]))
    state[RIP_INDEX] = CODE_BASE + functions[entry]['address']
    metadata = struct.unpack('<8Q', record[416:480])
    regions = [bytearray(record[480:576]), bytearray(record[576:])]
    sp, base = state[4], metadata[4]
    if sp >= base and sp - base <= STACK_BYTES - 8:
        offset = 16 + sp - base
        regions[1][offset:offset + 8] = ROOT_RETURN.to_bytes(8, 'little')
        if offset <= 16 + 496: regions[1][offset + 8:offset + 16] = state[6].to_bytes(8, 'little')
        if offset <= 16 + 488: regions[1][offset + 16:offset + 24] = state[2].to_bytes(8, 'little')
    return state, metadata, regions


def adjust_model(state, insn):
    instruction = scalar_for_adjust(insn)
    a, b = state[4], instruction.immediate & MASK64
    subtract = instruction.op == 'sub'
    signed = lambda value: value - (1 << 64) if value & (1 << 63) else value
    total = a - b if subtract else a + b
    signed_total = signed(a) - signed(b) if subtract else signed(a) + signed(b)
    result = total & MASK64
    cf = total < 0 if subtract else total > MASK64
    af = (a & 15) < (b & 15) if subtract else (a & 15) + (b & 15) > 15
    flags = int(cf) | (int((result & 255).bit_count() % 2 == 0) << 2) | (int(af) << 4)
    flags |= int(result == 0) << 6 | int(bool(result & (1 << 63))) << 7
    flags |= int(not -(1 << 63) <= signed_total < (1 << 63)) << 11
    state[4] = result
    state[RFLAGS_INDEX] = (state[RFLAGS_INDEX] & ~ARITHMETIC_FLAGS) | flags
    state[STATUS_INDEX] = 0


def model(program, entry, record):
    functions, decoded, calls, _ = program
    state, metadata, regions = prepare(record, entry, functions)
    maps = [metadata[:4], metadata[4:]]
    faults = [[0, 0], [0, 0]]
    valid = all(size <= limit and base + size <= MASK64 and rights <= 3 and not (size and null)
                for (base, size, rights, null), limit in zip(maps, (DATA_BYTES, STACK_BYTES)))
    db, dn, _, _ = maps[0]
    sb, sn, _, _ = maps[1]
    valid = valid and (not dn or not sn or db + dn <= sb or sb + sn <= db)
    state[STATUS_INDEX] = 0 if valid else 2

    def access(which, address, length, right, pc):
        base, size, rights, _ = maps[which]
        if address < base or address + length > base + size: state[STATUS_INDEX] = 1
        elif not rights & right: state[STATUS_INDEX] = 3
        else: return 16 + address - base
        faults[which] = [address, pc]
        return None

    def execute(name, expected):
        nonlocal state
        for insn in decoded[name]:
            offset = functions[name]['address'] + insn.pc
            pc, next_pc = CODE_BASE + offset, CODE_BASE + offset + len(insn.raw)
            state[RIP_INDEX] = pc
            if insn.op == 'gpr':
                state = list(STATE.unpack(gpr_model(insn.raw + b'\xc3', STATE.pack(*state))))
            elif insn.op == 'adjust':
                adjust_model(state, insn)
            elif insn.op == 'memory':
                memory = insn.memory
                address = effective_address(memory, state[:16])
                which = 1 if memory.base in (4, 5) else 0
                for i, (base, size, _, _) in enumerate(maps):
                    if base <= address < base + size:
                        which = i
                        break
                pos = access(which, address, memory.width // 8, 2 if memory.op == 'store' else 1, offset)
                if pos is None: return
                if memory.op == 'store':
                    value = state[memory.reg] & ((1 << memory.width) - 1)
                    regions[which][pos:pos + memory.width // 8] = value.to_bytes(memory.width // 8, 'little')
                else:
                    value = int.from_bytes(regions[which][pos:pos + memory.width // 8], 'little', signed=memory.op == 'signed_load')
                    mask = (1 << memory.destination_width) - 1
                    if memory.destination_width < 32: value = (state[memory.reg] & ~mask) | value
                    state[memory.reg] = value & (MASK64 if memory.destination_width < 32 else mask)
            elif insn.op in ('push', 'call'):
                address = (state[4] - 8) & MASK64
                value = state[insn.reg] if insn.op == 'push' else next_pc
                pos = access(1, address, 8, 2, offset)
                if pos is None: return
                regions[1][pos:pos + 8] = value.to_bytes(8, 'little')
                state[4] = address
                if insn.op == 'call':
                    execute(calls[name][insn.pc], next_pc)
                    if state[STATUS_INDEX]: return
            else:
                address = state[5 if insn.op == 'leave' else 4]
                pos = access(1, address, 8, 1, offset)
                if pos is None: return
                value = int.from_bytes(regions[1][pos:pos + 8], 'little')
                if insn.op == 'ret':
                    if value != expected:
                        state[STATUS_INDEX] = 4
                        faults[1] = [value, offset]
                        return
                    state[4] = (address + 8) & MASK64
                    state[RIP_INDEX] = value
                    return
                state[4] = value if insn.op == 'pop' and insn.reg == 4 else (address + 8) & MASK64
                if insn.op == 'leave': state[5] = value
                elif insn.reg != 4: state[insn.reg] = value
            state[RIP_INDEX] = next_pc
    if valid: execute(entry, ROOT_RETURN)
    return STATE.pack(*state) + struct.pack('<4Q', *faults[0], *faults[1]) + regions[0] + regions[1]


def make_record(a, b, sp_offset, index, *, data_size=64, stack_size=512, data_rights=3, stack_rights=3,
                data_null=0, stack_null=0, stack_base=STACK_BASE, rbp=None):
    bank = [((0x123456789abcdef * (r + 1)) ^ (index * 0x100000001)) & MASK64 for r in range(16)]
    bank[0], bank[2], bank[4], bank[6], bank[7] = a, b, (stack_base + sp_offset) & MASK64, a, DATA_BASE
    if rbp is not None: bank[5] = rbp
    cpu = make_state(index, bank, (index * 0x89) & ARITHMETIC_FLAGS)
    data = bytearray((i * 37 + index * 13) & 255 for i in range(96))
    data[16:24] = a.to_bytes(8, 'little')
    stack = bytes((i * 19 + index * 7) & 255 for i in range(544))
    return cpu + struct.pack('<8Q', DATA_BASE, data_size, data_rights, data_null,
                             stack_base, stack_size, stack_rights, stack_null) + data + stack


def corpus(random_count):
    records, descriptions = [], []
    def add(a, b, sp, **options):
        index = len(records)
        records.append(make_record(a, b, sp, index, **options))
        descriptions.append(dict(a=hex(a), b=hex(b), sp_offset=sp, **options))
    edge = [0, 1, 2, 15, 16, 255, 0x7fffffff, 0x80000000, 0xffffffff,
            0x100000000, (1 << 63) - 1, 1 << 63, MASK64, ROOT_RETURN]
    for a in edge:
        for b in edge:
            for sp in (120, 248, 440, 504): add(a, b, sp)
    for sp in (-16, -8, -1, 0, 1, 7, 8, 15, 16, 31, 63, 119, 120, 127, 248, 439, 440, 496, 503, 504, 505, 511, 512, 513, 520):
        for rights in range(4):
            for size in (0, 7, 8, 16, 64, 256, 511, 512):
                add(3, 7, sp, stack_size=size, stack_rights=rights)
    for size in (0, 1, 7, 8, 16, 31, 63, 64):
        for rights in range(4): add(11, 13, 440, data_size=size, data_rights=rights)
    for options in (dict(data_size=65), dict(stack_size=513), dict(data_rights=4), dict(stack_rights=4),
                    dict(data_null=1), dict(stack_null=1), dict(data_size=0, data_null=1),
                    dict(stack_size=0, stack_null=1), dict(stack_base=DATA_BASE),
                    dict(stack_base=MASK64 - 3), dict(stack_size=MASK64)):
        add(5, 9, 248, **options)
    for rbp in (STACK_BASE - 1, STACK_BASE, STACK_BASE + 8, STACK_BASE + 248, STACK_BASE + 504, STACK_BASE + 505):
        add(ROOT_RETURN, 1, 248, rbp=rbp)
    rng = random.Random(SEED)
    for _ in range(random_count):
        add(rng.getrandbits(64), rng.getrandbits(64), rng.randrange(-16, 528),
            data_size=rng.choice((8, 32, 64)), stack_size=rng.choice((64, 256, 512)),
            data_rights=rng.randrange(4), stack_rights=rng.randrange(4))
    return records, descriptions


def literal_cases(program):
    """Independent full snapshots, including persistent guest return addresses."""
    functions = program[0]
    cases = []

    def add(entry, *, a=3, b=7, sp=248, flags=0x8d5, options=None, updates=None,
            status=0, fault_pc=None, rip=None, fault=None, writes=None, new_flags=None, registers=None):
        record = make_record(a, b, sp, 100000 + len(cases), **(options or {}))
        initial = list(STATE.unpack(record[:416]))
        for reg, value in (registers or {}).items(): initial[reg] = value
        initial[RFLAGS_INDEX] = (initial[RFLAGS_INDEX] & ~ARITHMETIC_FLAGS) | flags
        record = STATE.pack(*initial) + record[416:]
        state, _, regions = prepare(record, entry, functions)
        for reg, value in (updates or {}).items(): state[reg] = value
        if status == 0: state[4] = (initial[4] + 8) & MASK64 if not updates or 4 not in updates else updates[4]
        state[STATUS_INDEX] = status
        state[RIP_INDEX] = (ROOT_RETURN if status == 0 else CODE_BASE + functions[entry]['address']) if rip is None else rip
        if fault_pc is not None: state[RIP_INDEX] = CODE_BASE + functions[entry]['address'] + fault_pc
        if new_flags is not None: state[RFLAGS_INDEX] = (state[RFLAGS_INDEX] & ~ARITHMETIC_FLAGS) | new_flags
        for which, offset, value in writes or []:
            if callable(value): value = value(initial)
            regions[which][16 + offset:16 + offset + 8] = value.to_bytes(8, 'little')
        faults = [0, 0, 0, 0]
        if fault:
            which, address, offset = fault
            faults[which * 2:which * 2 + 2] = [address, offset]
        cases.append((record, entry, STATE.pack(*state) + struct.pack('<4Q', *faults) + regions[0] + regions[1]))

    add('bare_ret', sp=504)
    for reg in range(16):
        add(f'push_pop_r{reg}', writes=[(1, 240, lambda initial, r=reg: initial[r])])
    off = functions['push_pop_r4']['address']
    add('push_pop_r4', options=dict(stack_rights=1), status=3, fault_pc=0,
        fault=(1, STACK_BASE + 240, off))
    add('push_pop_r4', options=dict(stack_rights=2), updates={4: STACK_BASE + 240}, status=3, fault_pc=1,
        fault=(1, STACK_BASE + 240, off + 1), writes=[(1, 240, STACK_BASE + 248)])
    add('push_pop_r0', sp=0, status=1, fault_pc=0,
        fault=(1, STACK_BASE - 8, functions['push_pop_r0']['address']))
    add('bare_ret', sp=505, status=1, fault_pc=0,
        fault=(1, STACK_BASE + 505, functions['bare_ret']['address']))
    add('bare_ret', options=dict(stack_size=513), status=2)
    add('bare_ret', options=dict(data_null=1), status=2)
    add('bare_ret', options=dict(stack_base=DATA_BASE), status=2)
    add('bare_leave', options=dict(rbp=STACK_BASE + 505), status=1, fault_pc=0,
        fault=(1, STACK_BASE + 505, functions['bare_leave']['address']))
    add('stack_arg7', a=MASK64, updates={0: MASK64})
    add('stack_args7_8', a=MASK64, b=1, updates={0: 0, 1: 1}, new_flags=0x55)
    add('framed_stack_args', updates={0: 10, 1: 7}, new_flags=4,
        writes=[(1, 240, lambda initial: initial[5])])
    add('stack_alias_arg', updates={0: 3, 8: STACK_BASE + 248})
    add('return_address', updates={0: ROOT_RETURN})
    continuation = CODE_BASE + functions['call_return_address']['address'] + 6
    add('call_return_address', updates={0: continuation},
        writes=[(1, 240, lambda initial: initial[3]), (1, 232, continuation)])
    continuation = CODE_BASE + functions['direct_call']['address'] + 6
    add('direct_call', writes=[(1, 240, lambda initial: initial[3]), (1, 232, continuation)])
    add('corrupt_return', a=0, status=4, fault_pc=4,
        fault=(1, 0, functions['corrupt_return']['address'] + 4), writes=[(1, 248, 0)])
    caller, callee = functions['caller_fault']['address'], functions['callee_data_fault']['address']
    add('caller_fault', updates={3: 3, 4: STACK_BASE + 232}, status=1, rip=CODE_BASE + callee,
        fault=(0, DATA_BASE + 64, callee),
        writes=[(1, 240, lambda initial: initial[3]), (1, 232, CODE_BASE + caller + 9)])
    add('negative_adjust8', new_flags=0x11)
    add('negative_adjust32', new_flags=0x11)
    add('adjust_zero', new_flags=0)
    continuation = CODE_BASE + functions['call_carry_flags']['address'] + 6
    add('call_carry_flags', a=MASK64, b=0, registers={1: 0}, updates={0: MASK64 - 1, 1: 1}, new_flags=0,
        writes=[(1, 240, lambda initial: initial[3]), (1, 232, continuation)])
    continuation = CODE_BASE + functions['call_logic_flags']['address'] + 6
    for a, result, flags in ((0, 7, 0x44), (1, 1, 0)):
        add('call_logic_flags', a=a, b=7, updates={0: result}, new_flags=flags,
            writes=[(1, 240, lambda initial: initial[3]), (1, 232, continuation)])
    return cases


def reference_sources(functions, decoded, calls):
    support = '''#include <stdint.h>
#include <string.h>
#include "cpu_state.h"
#include "guest_memory.h"
static int valid(BbGuestMemory *m, uint64_t limit) {
 return m->byte_size <= limit && m->guest_base <= UINT64_MAX - m->byte_size &&
        m->permissions <= 3 && (!m->byte_size || m->bytes);
}
static int access_ok(BbCpuState *s, BbGuestMemory *m, uint64_t a, uint64_t n, uint64_t right, uint64_t pc) {
 if (a < m->guest_base || a - m->guest_base > m->byte_size || n > m->byte_size - (a - m->guest_base)) s->status = 1;
 else if (!(m->permissions & right)) s->status = 3;
 else return 1;
 m->fault_address = a; m->fault_offset = pc; return 0;
}
static BbGuestMemory *choose(BbGuestMemory *d, BbGuestMemory *k, uint64_t a, int stack_fallback) {
 if (a >= d->guest_base && a - d->guest_base < d->byte_size) return d;
 if (a >= k->guest_base && a - k->guest_base < k->byte_size) return k;
 return stack_fallback ? k : d;
}
'''
    declarations = [f'static void checked_{name}(BbCpuState *, BbGuestMemory *, BbGuestMemory *, uint64_t);' for name in functions]
    assembly, bodies = [], []
    for name, instructions in decoded.items():
        lines = [f'static void checked_{name}(BbCpuState *s, BbGuestMemory *d, BbGuestMemory *k, uint64_t expected) {{', '(void)d;']
        for insn in instructions:
            offset = functions[name]['address'] + insn.pc
            pc, next_pc = CODE_BASE + offset, CODE_BASE + offset + len(insn.raw)
            lines.append(f's->rip = UINT64_C({pc});')
            if insn.op in ('gpr', 'adjust', 'memory', 'push', 'pop', 'leave'):
                helper = f'ss_original_{name}_{insn.pc}'
                declarations.append(f'extern void {helper}(BbCpuState *);')
                if insn.op == 'gpr':
                    assembly.append(oracle_assembly({helper: insn.raw + b'\xc3'}))
                else:
                    fake = bytes.fromhex('4801c4c3') if insn.op == 'adjust' else bytes.fromhex('4889c0c3')
                    wrapper = oracle_assembly({helper: fake})
                    marker = '.byte ' + ','.join(str(byte) for byte in fake[:-1])
                    if wrapper.count(marker) != 1: raise ValueError('oracle wrapper changed')
                    assembly.append(wrapper.replace(marker, '.byte ' + ','.join(str(byte) for byte in insn.raw)))
                if insn.op == 'memory':
                    memory = insn.memory
                    terms = [f'UINT64_C({memory.displacement & MASK64})']
                    if memory.base is not None: terms.append(f's->gpr[{memory.base}]')
                    if memory.index is not None: terms.append(f's->gpr[{memory.index}] * UINT64_C({memory.scale})')
                    lines += [f'uint64_t a{insn.pc} = ' + ' + '.join(terms) + ';',
                              f'BbGuestMemory *m{insn.pc} = choose(d, k, a{insn.pc}, {int(memory.base in (4, 5))});',
                              f'if (!access_ok(s, m{insn.pc}, a{insn.pc}, {memory.width // 8}, {2 if memory.op == "store" else 1}, {offset})) return;']
                elif insn.op in ('push', 'pop', 'leave'):
                    address = 's->gpr[4] - UINT64_C(8)' if insn.op == 'push' else f's->gpr[{5 if insn.op == "leave" else 4}]'
                    lines.append(f'if (!access_ok(s, k, {address}, 8, {2 if insn.op == "push" else 1}, {offset})) return;')
                lines.append(f'{helper}(s);')
            elif insn.op == 'call':
                lines += [f'uint64_t a{insn.pc} = s->gpr[4] - UINT64_C(8);',
                          f'if (!access_ok(s, k, a{insn.pc}, 8, 2, {offset})) return;',
                          f'uint64_t r{insn.pc} = UINT64_C({next_pc});',
                          f'memcpy(k->bytes + (a{insn.pc} - k->guest_base), &r{insn.pc}, 8);',
                          f's->gpr[4] = a{insn.pc};',
                          f'checked_{calls[name][insn.pc]}(s, d, k, UINT64_C({next_pc}));',
                          'if (s->status) return;']
            else:
                lines += [f'if (!access_ok(s, k, s->gpr[4], 8, 1, {offset})) return;',
                          f'uint64_t r{insn.pc}; memcpy(&r{insn.pc}, k->bytes + (s->gpr[4] - k->guest_base), 8);',
                          f'if (r{insn.pc} != expected) {{ s->status = 4; k->fault_address = r{insn.pc}; k->fault_offset = {offset}; return; }}',
                          f's->gpr[4] += UINT64_C(8); s->rip = r{insn.pc}; return;']
            if insn.op != 'ret': lines.append(f's->rip = UINT64_C({next_pc});')
        lines.append('}')
        bodies.append('\n'.join(lines))
        bodies.append(f'''void entry_{name}(BbCpuState *s, BbGuestMemory *d, BbGuestMemory *k) {{
 d->fault_address = d->fault_offset = k->fault_address = k->fault_offset = 0;
 if (!valid(d, 64) || !valid(k, 512) || (d->byte_size && k->byte_size &&
     !(d->guest_base + d->byte_size <= k->guest_base || k->guest_base + k->byte_size <= d->guest_base))) {{ s->status = 2; return; }}
 s->status = 0; checked_{name}(s, d, k, UINT64_C({ROOT_RETURN}));
}}''')
    return '\n'.join(assembly), support + '\n'.join(declarations + bodies)


def final_flags(name, decoded, calls, mask=ARITHMETIC_FLAGS):
    for insn in decoded[name]:
        if insn.op == 'adjust': mask = ARITHMETIC_FLAGS
        elif insn.op == 'gpr':
            op = decode_gpr(insn.raw + b'\xc3')[0].op
            if op in ('and', 'or', 'xor', 'test'): mask = ARITHMETIC_FLAGS & ~16
            elif op not in ('mov', 'cmov'): mask = ARITHMETIC_FLAGS
        elif insn.op == 'call': mask = final_flags(calls[name][insn.pc], decoded, calls, mask)
    return mask


def whole_native_bridge(functions, decoded, calls):
    names = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
    saved = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')
    lines = ['.text']
    for name, function in functions.items():
        lines += [f'.globl _native_{name}', f'_native_{name}:'] + [f'pushq %{r}' for r in saved]
        lines += ['movq %rdi, %xmm15', 'movq %rsp, %xmm14',
                  f'movq ${final_flags(name, decoded, calls)}, %rax', 'movq %rax, %xmm10',
                  'movq 392(%rdi), %rax', 'andq $0x8d5, %rax', 'orq $0x202, %rax', 'pushq %rax', 'popfq']
        lines += [f'movq {i * 8}(%rdi), %{r}' for i, r in enumerate(names) if r != 'rdi']
        lines += ['movq 56(%rdi), %rdi', f'jmp *Ltarget_{name}(%rip)',
                  f'Ltarget_{name}:', f'.quad {CODE_BASE + function["address"]}']
    lines += ['.globl _ss_native_capture', '_ss_native_capture:',
              'movq %rax, %xmm12', 'movq %rsp, %xmm13', 'movq %xmm14, %rsp', 'movq %xmm15, %rax']
    lines += [f'movq %{r}, {i * 8}(%rax)' for i, r in enumerate(names) if r not in ('rax', 'rsp')]
    lines += ['movq %xmm12, %rdx', 'movq %rdx, 0(%rax)', 'movq %xmm13, %rdx', 'movq %rdx, 32(%rax)',
              'pushfq', 'popq %rdx', 'movq %xmm10, %rcx', 'andq %rcx, %rdx', 'movq 392(%rax), %rcx',
              f'andq ${-1 ^ ARITHMETIC_FLAGS}, %rcx', 'orq %rdx, %rcx', 'movq %rcx, 392(%rax)',
              f'movabsq ${ROOT_RETURN}, %rdx', 'movq %rdx, 384(%rax)', 'movl $0, 404(%rax)']
    lines += [f'popq %{r}' for r in reversed(saved)] + ['ret']
    return '\n'.join(lines) + '\n'


def entry_header(specification, functions):
    names = list(functions)
    lines = ['#include <stdint.h>', f'#define SS_ENTRIES {len(names)}',
             f'#define SS_DATA_BASE UINT64_C({DATA_BASE})', f'#define SS_STACK_BASE UINT64_C({STACK_BASE})',
             f'#define SS_CODE_BASE UINT64_C({CODE_BASE})', f'#define SS_ROOT_RETURN UINT64_C({ROOT_RETURN})']
    lines.extend(f'extern void entry_{name}(BbCpuState *, BbGuestMemory *, BbGuestMemory *);' for name in names)
    lines += ['static void (*ss_entries[])(BbCpuState *, BbGuestMemory *, BbGuestMemory *) = {' + ','.join('entry_' + n for n in names) + '};',
              'static const uint64_t ss_offsets[] = {' + ','.join(str(functions[n]['address']) for n in names) + '};',
              'static const unsigned ss_abi[] = {' + ','.join(str(int(specification[n].get('abi', True))) for n in names) + '};', '#ifdef ORIGINAL']
    lines.extend(f'extern void native_{name}(BbCpuState *);' for name in names)
    lines += ['extern void ss_native_capture(void);',
              'static void (*ss_native_entries[])(BbCpuState *) = {' + ','.join('native_' + n for n in names) + '};']
    image = bytearray(b'\xcc' * (0x10000 + 14))
    for function in functions.values(): image[function['address']:function['address'] + len(function['code'])] = function['code']
    image[0x10000:] = bytes.fromhex('ff2500000000') + b'\x00' * 8
    lines += ['static const unsigned char ss_image[] = {',
              *[','.join(str(v) for v in image[i:i + 24]) + ',' for i in range(0, len(image), 24)], '};', '#endif']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/recompiler-state-stack')
    parser.add_argument('--random-count', type=int, default=256)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.random_count < 0: parser.error('--random-count must be nonnegative')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'verification.json'
    report = {'status': 'incomplete', 'scope': 'bounded common-state stack/direct calls; no game execution',
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'commands': [], 'steps': []}
    def save(): report_path.write_text(json.dumps(report, indent=2) + '\n')
    def command(label, argv, inputs=None):
        argv = [str(v) for v in argv]
        print(label, flush=True)
        report['commands'].append(argv)
        save()
        output = out / (label + ('.bin' if inputs is not None else '.stdout.log'))
        with output.open('wb') as stream:
            result = subprocess.run(argv, input=inputs, stdout=stream, stderr=subprocess.PIPE, timeout=300)
        (out / (label + '.stderr.log')).write_bytes(result.stderr)
        report['steps'].append(dict(name=label, exit_code=result.returncode))
        save()
        if result.returncode: raise RuntimeError(f'{label}: exit {result.returncode}; inspect stderr log')
        return output
    save()
    try:
        if platform.system() != 'Darwin' or platform.machine() != 'arm64': raise RuntimeError('use native ARM64 Python on Apple Silicon')
        spec = json.loads((ROOT / 'state_stack_fixtures.json').read_text())
        ir, functions, decoded, calls, costs = lift(spec)
        program = functions, decoded, calls, costs
        names = list(functions)
        (out / 'state_stack.ll').write_text(ir)
        (out / 'cpu_state_layout.h').write_text(c_layout_checks())
        (out / 'state_stack_entries.h').write_text(entry_header(spec, functions))
        assembly, source = reference_sources(functions, decoded, calls)
        (out / 'original.s').write_text(assembly + whole_native_bridge(functions, decoded, calls))
        (out / 'original.c').write_text(source)
        (out / 'module.json').write_text(json.dumps({n: dict(address=f['address'], code=f['code'].hex()) for n, f in functions.items()}, indent=2))
        records, descriptions = corpus(args.random_count)
        known = []
        for record, entry, expected in literal_cases(program):
            index = len(records)
            records.append(record)
            descriptions.append(dict(literal_answer=entry))
            known.append((index, entry, expected))
        inputs = b''.join(records)
        (out / 'inputs.bin').write_bytes(inputs)
        (out / 'inputs.json').write_text(json.dumps(descriptions, indent=2) + '\n')
        (out / 'known-answers.json').write_text(json.dumps([
            dict(input_index=i, entry=name, expected=expected.hex()) for i, name, expected in known], indent=2))
        outputs = {}
        for label, arch in (('original-x86_64', 'x86_64'), ('aot-x86_64', 'x86_64'), ('aot-arm64', 'arm64')):
            argv = ['xcrun', 'clang', '-arch', arch, '-std=c11', '-O2', '-Wall', '-Wextra', '-I', ROOT, '-I', out,
                    ROOT / 'state_stack_harness.c']
            argv += ['-DORIGINAL', out / 'original.s', out / 'original.c'] if label.startswith('original') else [out / 'state_stack.ll']
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
                    pos = (index * len(names) + names.index(name)) * OUTPUT_BYTES
                    if data[pos:pos + OUTPUT_BYTES] != expected:
                        (out / 'known-mismatch.json').write_text(json.dumps(dict(backend=label, entry=name, input_index=index,
                            expected=expected.hex(), actual=data[pos:pos + OUTPUT_BYTES].hex()), indent=2))
                        raise RuntimeError(f'{label}: literal snapshot mismatch at {name}')
        reference = outputs['original-x86_64']
        for label, path in outputs.items():
            with reference.open('rb') as left, path.open('rb') as right:
                offset = 0
                while a := left.read(1024 * 1024):
                    b = right.read(len(a))
                    if a != b:
                        first = offset + next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
                        index, f = divmod(first // OUTPUT_BYTES, len(names))
                        report['mismatch'] = dict(backend=label, input_index=index, input=descriptions[index], entry=names[f], snapshot_byte=first % OUTPUT_BYTES)
                        raise RuntimeError(f'{label}: mismatch at {names[f]}, input {index}')
                    offset += len(a)
        independent, counts = 0, [0] * 5
        coverage = {name: [0] * 5 for name in names}
        with reference.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for i, record in enumerate(records):
                for f, name in enumerate(names):
                    position = (i * len(names) + f) * OUTPUT_BYTES
                    status, = struct.unpack('<I', data[position + OFFSETS['status']:position + OFFSETS['status'] + 4])
                    coverage[name][status] += 1
                    counts[status] += 1
                    expected = model(program, name, record)
                    if data[position:position + OUTPUT_BYTES] != expected:
                        report['model_mismatch'] = dict(input_index=i, input=descriptions[i], entry=name)
                        raise RuntimeError(f'independent model mismatch at {name}, input {i}')
                    independent += 1
        hashes = {label: sha(path) for label, path in outputs.items()}
        if len(set(hashes.values())) != 1: raise RuntimeError('result hashes differ')
        native_match = re.search(r'whole-native=(\d+)', (out / 'original-x86_64-run.stderr.log').read_text())
        if native_match is None or int(native_match[1]) != counts[0] or not counts[0]:
            raise RuntimeError('whole-native x86 success verification count missing or inconsistent')
        archive = out / ('snapshots-' + hashes['original-x86_64'] + '.bin.gz')
        print('archive-results', flush=True)
        with reference.open('rb') as src, gzip.open(archive, 'wb', compresslevel=1) as dst:
            while chunk := src.read(4 * 1024 * 1024): dst.write(chunk)
        with gzip.open(archive, 'rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != hashes['original-x86_64']: raise RuntimeError('archive mismatch')
        report.update(host=platform.platform(), machine=platform.machine(), cpu_state_bytes=STATE.size, stack_bytes=STACK_BYTES,
                      data_bytes=DATA_BYTES, code_base=hex(CODE_BASE), root_return=hex(ROOT_RETURN),
                      input_record_bytes=INPUT_BYTES, snapshot_bytes=OUTPUT_BYTES, seed=hex(SEED), entries=len(names), input_states=len(records),
                      comparisons_per_aot_backend=len(records) * len(names), independent_model_snapshots=independent,
                      outcome_counts=dict(zip(('success', 'bounds', 'invalid_descriptor', 'denied', 'return_rejected'), counts)),
                      per_entry_outcomes=coverage, expanded_steps=costs, native_ubsan=args.sanitize,
                      whole_native_x86_success_checks=int(native_match[1]), literal_answers_per_backend=len(known), mismatches=0,
                      oracle='Independent checked C + actual x86 instructions; every success replayed as a whole native function with real CALL/RET and guest return addresses.',
                      source_sha256={str((ROOT / n).relative_to(ROOT.parent)): sha(ROOT / n) for n in
                          ('state_stack_lift.py', 'state_stack_harness.c', 'run_state_stack.py', 'state_stack_fixtures.json',
                           'cpu_state.h', 'cpu_state.py', 'gpr_lift.py', 'run_gpr.py', 'state_memory_lift.py', 'guest_memory.h', 'stack_lift.py', 'memory_lift.py')},
                      inputs_sha256=sha(out / 'inputs.bin'), results_sha256=hashes,
                      result_archive=dict(path=archive.name, compression='gzip', sha256=sha(archive),
                                          uncompressed_sha256=hashes['original-x86_64'], uncompressed_bytes=expected_size))
        compiler = command('compiler', ['xcrun', 'clang', '--version'])
        report['compiler'] = compiler.read_text()
        report['status'] = 'passed'
        save()
        for path in outputs.values(): path.unlink()
        print(f'PASS: {len(records) * len(names)} complete stack snapshots per backend, zero differences; {report_path}', flush=True)
    except Exception as error:
        report.update(status='failed', error=str(error))
        save()
        raise


if __name__ == '__main__': main()
