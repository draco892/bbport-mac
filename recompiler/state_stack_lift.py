"""Bounded direct CALL/RET and explicit guest stack in common CPU-state ABI v1."""
from dataclasses import dataclass
from cpu_state import OFFSETS
from gpr_lift import (decode as decode_gpr, lift as lift_gpr, lift_instructions,
                      Instruction as ScalarInstruction, DECLARATIONS)
from state_memory_lift import decode as decode_memory, lift as lift_memory
from stack_lift import assemble

CODE_BASE = 0x600000000
ROOT_RETURN = CODE_BASE + 0x10000
DATA_BYTES, STACK_BYTES = 64, 512
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Instruction:
    pc: int
    raw: bytes
    op: str
    reg: int = 0
    amount: int = 0
    target: int = 0
    memory: object = None


def decode(code):
    if not code or len(code) > 4096: raise ValueError('expected 1..4096 code bytes')
    instructions, pc = [], 0
    while pc < len(code):
        start = pc
        if code[pc] == 0xc3:
            if pc != len(code) - 1: raise ValueError('unreachable code after RET')
            instructions.append(Instruction(pc, b'\xc3', 'ret'))
            return instructions
        if code[pc] == 0xe8:
            if pc + 5 > len(code): raise ValueError('truncated CALL rel32')
            raw = code[pc:pc + 5]
            target = pc + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            instructions.append(Instruction(pc, raw, 'call', target=target))
            pc += 5
            continue
        if code[pc] == 0xc9:
            instructions.append(Instruction(pc, b'\xc9', 'leave'))
            pc += 1
            continue
        if code[pc] == 0x41 and pc + 1 < len(code) and 0x50 <= code[pc + 1] <= 0x5f:
            opcode, size, high = code[pc + 1], 2, 8
        elif 0x50 <= code[pc] <= 0x5f:
            opcode, size, high = code[pc], 1, 0
        else:
            opcode, size, high = 0, 0, 0
        if size:
            instructions.append(Instruction(pc, code[pc:pc + size], 'pop' if opcode >= 0x58 else 'push',
                                            reg=(opcode & 7) + high))
            pc += size
            continue
        if code[pc:pc + 3] in (b'\x48\x83\xc4', b'\x48\x83\xec', b'\x48\x81\xc4', b'\x48\x81\xec'):
            size = 4 if code[pc + 1] == 0x83 else 7
            if pc + size > len(code): raise ValueError('truncated RSP adjustment')
            amount = int.from_bytes(code[pc + 3:pc + size], 'little', signed=True)
            instructions.append(Instruction(pc, code[pc:pc + size], 'adjust',
                                            amount=amount if code[pc + 2] == 0xc4 else -amount))
            pc += size
            continue
        found = False
        for size in range(2, 5):
            raw = code[pc:pc + size]
            if len(raw) != size: continue
            try:
                decoded = decode_gpr(raw + b'\xc3')
            except ValueError:
                continue
            if len(decoded) == 1:
                instructions.append(Instruction(pc, raw, 'gpr'))
                pc += size
                found = True
                break
        if found: continue
        for size in range(2, 12):
            raw = code[pc:pc + size]
            if len(raw) != size: continue
            try:
                memory = decode_memory(raw + b'\xc3')
            except ValueError:
                continue
            if len(memory) == 1 and memory[0].op != 'gpr':
                instructions.append(Instruction(pc, raw, 'memory', memory=memory[0]))
                pc += size
                found = True
                break
        if not found: raise ValueError(f'unsupported stack instruction at {start:#x}')
    raise ValueError('missing final RET')


def analyze(specification):
    functions = assemble(specification)
    if not 1 <= len(functions) <= 128: raise ValueError('expected 1..128 known functions')
    decoded, addresses = {}, {}
    for name, function in functions.items():
        if not name.isidentifier() or not name.isascii(): raise ValueError('invalid function name')
        address = function['address']
        if type(address) is not int or address < 0 or address + len(function['code']) > 0x10000:
            raise ValueError('function outside bounded code image')
        if address in addresses: raise ValueError('duplicate function address')
        addresses[address] = name
        decoded[name] = decode(function['code'])
    spans = sorted((f['address'], f['address'] + len(f['code'])) for f in functions.values())
    if any(b[0] < a[1] for a, b in zip(spans, spans[1:])): raise ValueError('overlapping functions')
    calls = {}
    for name, instructions in decoded.items():
        calls[name] = {}
        for insn in instructions:
            if insn.op == 'call':
                offset = functions[name]['address'] + insn.target
                if offset not in addresses: raise ValueError('CALL must target a registered function entry')
                calls[name][insn.pc] = addresses[offset]
    complete, visiting, costs, depths = set(), set(), {}, {}

    def visit(name):
        if name in visiting: raise ValueError('recursive call graph outside bounded contract')
        if name in complete: return
        visiting.add(name)
        cost, depth = len(decoded[name]), 1
        for callee in calls[name].values():
            visit(callee)
            cost += costs[callee]
            depth = max(depth, 1 + depths[callee])
        if depth > 16 or cost > 4096: raise ValueError('expanded call graph exceeds bounded execution budget')
        visiting.remove(name)
        complete.add(name)
        costs[name], depths[name] = cost, depth
    for name in functions: visit(name)
    return functions, decoded, calls, costs


def scalar_for_adjust(insn):
    # Keep the original ADD/SUB operation, not merely its net delta: flags differ
    # for SUB negative-immediate vs ADD positive-immediate.
    immediate = int.from_bytes(insn.raw[3:], 'little', signed=True)
    op = 'add' if insn.raw[2] == 0xc4 else 'sub'
    return ScalarInstruction(op, 4, 0, 64, immediate=immediate)


def support_ir():
    return '''
define i1 @ss_valid(ptr %map, i64 %limit) {
 %pp = getelementptr i8, ptr %map, i64 0
 %bp = getelementptr i8, ptr %map, i64 8
 %np = getelementptr i8, ptr %map, i64 16
 %rp = getelementptr i8, ptr %map, i64 24
 %bytes = load ptr, ptr %pp
 %base = load i64, ptr %bp
 %size = load i64, ptr %np
 %rights = load i64, ptr %rp
 %small = icmp ule i64 %size, %limit
 %last = sub i64 -1, %size
 %nowrap = icmp ule i64 %base, %last
 %known = icmp ule i64 %rights, 3
 %nonnull = icmp ne ptr %bytes, null
 %empty = icmp eq i64 %size, 0
 %buffer = or i1 %nonnull, %empty
 %v0 = and i1 %small, %nowrap
 %v1 = and i1 %known, %buffer
 %valid = and i1 %v0, %v1
 ret i1 %valid
}
define i1 @ss_access(ptr %state, ptr %map, i64 %address, i64 %right, i64 %pc) {
 %bp = getelementptr i8, ptr %map, i64 8
 %np = getelementptr i8, ptr %map, i64 16
 %rp = getelementptr i8, ptr %map, i64 24
 %base = load i64, ptr %bp
 %size = load i64, ptr %np
 %rights = load i64, ptr %rp
 %offset = sub i64 %address, %base
 %above = icmp uge i64 %address, %base
 %enough = icmp uge i64 %size, 8
 %last = sub i64 %size, 8
 %fits = icmp ule i64 %offset, %last
 %b0 = and i1 %above, %enough
 %bounded = and i1 %b0, %fits
 br i1 %bounded, label %permission, label %bounds
bounds:
 %status1 = getelementptr i8, ptr %state, i64 404
 store i32 1, ptr %status1
 br label %fault
permission:
 %present = and i64 %rights, %right
 %allowed = icmp ne i64 %present, 0
 br i1 %allowed, label %ok, label %denied
denied:
 %status3 = getelementptr i8, ptr %state, i64 404
 store i32 3, ptr %status3
 br label %fault
fault:
 %ap = getelementptr i8, ptr %map, i64 32
 %fp = getelementptr i8, ptr %map, i64 40
 store i64 %address, ptr %ap
 store i64 %pc, ptr %fp
 ret i1 false
ok:
 ret i1 true
}
define i64 @ss_read(ptr %state, ptr %map, i64 %address, i64 %pc) {
 %ok = call i1 @ss_access(ptr %state, ptr %map, i64 %address, i64 1, i64 %pc)
 br i1 %ok, label %read, label %failed
read:
 %basep = getelementptr i8, ptr %map, i64 8
 %base = load i64, ptr %basep
 %bytes = load ptr, ptr %map
 %offset = sub i64 %address, %base
 %host = getelementptr i8, ptr %bytes, i64 %offset
 %value = load i64, ptr %host, align 1
 ret i64 %value
failed:
 ret i64 0
}
define void @ss_write(ptr %state, ptr %map, i64 %address, i64 %value, i64 %pc) {
 %ok = call i1 @ss_access(ptr %state, ptr %map, i64 %address, i64 2, i64 %pc)
 br i1 %ok, label %write, label %failed
write:
 %basep = getelementptr i8, ptr %map, i64 8
 %base = load i64, ptr %basep
 %bytes = load ptr, ptr %map
 %offset = sub i64 %address, %base
 %host = getelementptr i8, ptr %bytes, i64 %offset
 store i64 %value, ptr %host, align 1
 br label %failed
failed:
 ret void
}
define ptr @ss_select(ptr %data, ptr %stack, i64 %address, i1 %stack_fallback) {
 %dbp = getelementptr i8, ptr %data, i64 8
 %dnp = getelementptr i8, ptr %data, i64 16
 %sbp = getelementptr i8, ptr %stack, i64 8
 %snp = getelementptr i8, ptr %stack, i64 16
 %db = load i64, ptr %dbp
 %dn = load i64, ptr %dnp
 %sb = load i64, ptr %sbp
 %sn = load i64, ptr %snp
 %do = sub i64 %address, %db
 %so = sub i64 %address, %sb
 %dlo = icmp uge i64 %address, %db
 %slo = icmp uge i64 %address, %sb
 %dhi = icmp ult i64 %do, %dn
 %shi = icmp ult i64 %so, %sn
 %din = and i1 %dlo, %dhi
 %sin = and i1 %slo, %shi
 %fallback = select i1 %stack_fallback, ptr %stack, ptr %data
 %notdata = select i1 %sin, ptr %stack, ptr %fallback
 %result = select i1 %din, ptr %data, ptr %notdata
 ret ptr %result
}
'''


def lift(specification):
    functions, decoded, calls, costs = analyze(specification)
    module = [DECLARATIONS, support_ir()]
    for name, instructions in decoded.items():
        lines = [f'define void @ss_{name}(ptr %state, ptr %data, ptr %stack, i64 %expected) {{', 'entry:']
        serial = 0

        def emit(expression):
            nonlocal serial
            serial += 1
            result = f'%s{serial}'
            lines.append(f'  {result} = {expression}')
            return result

        regs = [emit(f'getelementptr i8, ptr %state, i64 {r * 8}') for r in range(16)]
        rip = emit(f'getelementptr i8, ptr %state, i64 {OFFSETS["rip"]}')
        status = emit(f'getelementptr i8, ptr %state, i64 {OFFSETS["status"]}')

        def read(reg): return emit(f'load i64, ptr {regs[reg]}, align 1')
        def write(reg, value): lines.append(f'  store i64 {value}, ptr {regs[reg]}, align 1')

        def check():
            value = emit(f'load i32, ptr {status}, align 1')
            good = emit(f'icmp eq i32 {value}, 0')
            label = f'continue{serial}'
            lines.extend([f'  br i1 {good}, label %{label}, label %halt', f'{label}:'])

        for insn in instructions:
            offset = functions[name]['address'] + insn.pc
            pc, next_pc = CODE_BASE + offset, CODE_BASE + offset + len(insn.raw)
            lines.append(f'  store i64 {pc}, ptr {rip}, align 1')
            if insn.op in ('gpr', 'adjust'):
                helper = f'ss_{name}_scalar_{insn.pc}'
                module.append(lift_gpr(insn.raw + b'\xc3', helper) if insn.op == 'gpr'
                              else lift_instructions([scalar_for_adjust(insn)], helper))
                lines.append(f'  call void @{helper}(ptr %state)')
            elif insn.op == 'memory':
                memory = insn.memory
                address = str(memory.displacement)
                if memory.base is not None:
                    address = emit(f'add i64 {read(memory.base)}, {memory.displacement}')
                if memory.index is not None:
                    scaled = emit(f'mul i64 {read(memory.index)}, {memory.scale}')
                    address = emit(f'add i64 {address}, {scaled}')
                chosen = emit(f'call ptr @ss_select(ptr %data, ptr %stack, i64 {address}, i1 {"true" if memory.base in (4, 5) else "false"})')
                helper = f'ss_{name}_memory_{insn.pc}'
                module.append(lift_memory(insn.raw + b'\xc3', helper, max_bytes=STACK_BYTES))
                lines.append(f'  call void @{helper}(ptr %state, ptr {chosen})')
                value = emit(f'load i32, ptr {status}, align 1')
                good = emit(f'icmp eq i32 {value}, 0')
                label = f'memory_ok{serial}'
                lines.extend([f'  br i1 {good}, label %{label}, label %memory_fault{insn.pc}', f'memory_fault{insn.pc}:'])
                fault = emit(f'getelementptr i8, ptr {chosen}, i64 40')
                lines += [f'  store i64 {offset}, ptr {fault}', '  ret void', f'{label}:']
            elif insn.op in ('push', 'call'):
                sp = read(4)
                address = emit(f'sub i64 {sp}, 8')
                value = read(insn.reg) if insn.op == 'push' else str(next_pc)
                lines.append(f'  call void @ss_write(ptr %state, ptr %stack, i64 {address}, i64 {value}, i64 {offset})')
                check()
                write(4, address)
                if insn.op == 'call':
                    callee = calls[name][insn.pc]
                    lines.append(f'  call void @ss_{callee}(ptr %state, ptr %data, ptr %stack, i64 {next_pc})')
                    check()
            elif insn.op in ('pop', 'leave', 'ret'):
                address = read(5 if insn.op == 'leave' else 4)
                value = emit(f'call i64 @ss_read(ptr %state, ptr %stack, i64 {address}, i64 {offset})')
                check()
                if insn.op == 'ret':
                    expected = emit(f'icmp eq i64 {value}, %expected')
                    lines += [f'  br i1 {expected}, label %return_ok, label %return_bad', 'return_bad:',
                              f'  store i32 4, ptr {status}, align 1']
                    bad_address = emit('getelementptr i8, ptr %stack, i64 32')
                    bad_pc = emit('getelementptr i8, ptr %stack, i64 40')
                    lines += [f'  store i64 {value}, ptr {bad_address}', f'  store i64 {offset}, ptr {bad_pc}',
                              '  ret void', 'return_ok:']
                    advanced = emit(f'add i64 {address}, 8')
                    write(4, advanced)
                    lines += [f'  store i64 {value}, ptr {rip}, align 1', '  ret void']
                else:
                    advanced = emit(f'add i64 {address}, 8')
                    write(4, value if insn.op == 'pop' and insn.reg == 4 else advanced)
                    if insn.op == 'leave': write(5, value)
                    elif insn.reg != 4: write(insn.reg, value)
            if insn.op != 'ret': lines.append(f'  store i64 {next_pc}, ptr {rip}, align 1')
        lines += ['halt:', '  ret void', '}']
        module.append('\n'.join(lines))
        # Both descriptors are validated before any root instruction executes.
        entry = [f'define void @entry_{name}(ptr %state, ptr %data, ptr %stack) {{', 'entry:',
                 ' %dvalid = call i1 @ss_valid(ptr %data, i64 64)',
                 ' %svalid = call i1 @ss_valid(ptr %stack, i64 512)',
                 ' %v = and i1 %dvalid, %svalid']
        for prefix, parameter in (('d', 'data'), ('s', 'stack')):
            entry += [f' %{prefix}bp = getelementptr i8, ptr %{parameter}, i64 8',
                      f' %{prefix}np = getelementptr i8, ptr %{parameter}, i64 16',
                      f' %{prefix}b = load i64, ptr %{prefix}bp', f' %{prefix}n = load i64, ptr %{prefix}np',
                      f' %{prefix}end = add i64 %{prefix}b, %{prefix}n',
                      f' %{prefix}empty = icmp eq i64 %{prefix}n, 0',
                      f' %{prefix}ap = getelementptr i8, ptr %{parameter}, i64 32',
                      f' %{prefix}fp = getelementptr i8, ptr %{parameter}, i64 40',
                      f' store i64 0, ptr %{prefix}ap', f' store i64 0, ptr %{prefix}fp']
        entry += [' %before = icmp ule i64 %dend, %sb', ' %after = icmp ule i64 %send, %db',
                  ' %separate = or i1 %before, %after', ' %empty = or i1 %dempty, %sempty',
                  ' %disjoint = or i1 %separate, %empty', ' %valid = and i1 %v, %disjoint',
                  ' %status = getelementptr i8, ptr %state, i64 404',
                  ' br i1 %valid, label %body, label %invalid', 'invalid:', ' store i32 2, ptr %status',
                  ' ret void', 'body:', ' store i32 0, ptr %status',
                  f' call void @ss_{name}(ptr %state, ptr %data, ptr %stack, i64 {ROOT_RETURN})', ' ret void', '}']
        module.append('\n'.join(entry))
    return '\n\n'.join(module), functions, decoded, calls, costs
