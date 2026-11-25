"""Bounded control flow, calls and explicit guest stack in CPU-state ABI v1."""
from dataclasses import dataclass
from cpu_state import OFFSETS, xmm_offset
from gpr_lift import (decode as decode_gpr, lift as lift_gpr, lift_instructions,
                      Instruction as ScalarInstruction, DECLARATIONS, MAX_ENCODING_BYTES)
from state_memory_lift import decode as decode_memory, lift as lift_memory
from stack_lift import assemble
from x86_address import decode_address
from simd_lift import (decode as decode_simd, lift as lift_simd,
                       declarations as simd_declarations, FP_IDS)

CODE_BASE = 0x600000000
ROOT_RETURN = CODE_BASE + 0x10000
DATA_BYTES, STACK_BYTES = 64, 512
HOST_IMPORT = 0x10010
STEP_LIMIT = 4096
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


def decode(code, *, real=False):
    if not code or len(code) > 4096: raise ValueError('expected 1..4096 code bytes')
    instructions, pc = [], 0
    while pc < len(code):
        start = pc
        if code[pc] == 0xc3:
            if not real and pc != len(code) - 1: raise ValueError('unreachable code after RET')
            instructions.append(Instruction(pc, b'\xc3', 'ret'))
            if pc == len(code) - 1: return instructions
            pc += 1
            continue
        if code[pc] == 0xe8:
            if pc + 5 > len(code): raise ValueError('truncated CALL rel32')
            raw = code[pc:pc + 5]
            target = pc + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            instructions.append(Instruction(pc, raw, 'call', target=target))
            pc += 5
            continue
        opcode = code[pc]
        near = opcode in (0xeb, 0xe9) or 0x70 <= opcode <= 0x7f
        long_condition = opcode == 0x0f and pc + 1 < len(code) and 0x80 <= code[pc + 1] <= 0x8f
        if near or long_condition:
            prefix = 2 if long_condition else 1
            width = 4 if opcode == 0xe9 or long_condition else 1
            end = pc + prefix + width
            if end > len(code): raise ValueError('truncated branch')
            cc = (code[pc + prefix - 1] & 15) if long_condition or 0x70 <= opcode <= 0x7f else -1
            delta = int.from_bytes(code[pc + prefix:end], 'little', signed=True)
            instructions.append(Instruction(pc, code[pc:end], 'branch', amount=cc, target=end + delta))
            pc = end
            continue
        rex_size = int(0x40 <= opcode <= 0x4f)
        rex = opcode if rex_size else 0
        ff = pc + rex_size
        if ff + 1 < len(code) and code[ff] == 0xff and (code[ff + 1] >> 3) & 7 == 2:
            if rex & 4: raise ValueError('REX.R on indirect CALL opcode extension')
            modrm = code[ff + 1]
            if modrm >> 6 == 3:
                if rex & 2: raise ValueError('REX.X on register CALL')
                end = ff + 2
                instructions.append(Instruction(pc, code[pc:end], 'indirect', reg=(modrm & 7) + (8 if rex & 1 else 0)))
                pc = end
                continue
            # Reuse MOV's checked memory decoder for the qword CALL operand.
            for end in range(ff + 2, min(len(code), ff + 7) + 1):
                fake = bytes((0x48 | (rex & 3), 0x8b, modrm & 0xc7)) + code[ff + 2:end] + b'\xc3'
                try:
                    operand, = decode_memory(fake, allow_rip=real)
                except ValueError:
                    continue
                instructions.append(Instruction(pc, code[pc:end], 'indirect', memory=operand))
                pc = end
                break
            else:
                raise ValueError('unsupported indirect CALL memory operand')
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
        if code[pc:pc + 2] in (b'\x0f\x0b', b'\x0f\xae') and (
                code[pc + 1] == 0x0b or code[pc:pc + 3] == b'\x0f\xae\xf0'):
            op = 'ud2' if code[pc + 1] == 0x0b else 'fence'
            end = pc + (2 if op == 'ud2' else 3)
            instructions.append(Instruction(pc, code[pc:end], op))
            pc = end
            continue
        if real:
            rex = code[pc] if 0x40 <= code[pc] <= 0x4f else 0
            opcode = pc + bool(rex)
            if opcode + 1 < len(code) and code[opcode] == 0x8d:
                modrm = code[opcode + 1]
                addr, end = decode_address(code, opcode + 2, modrm, rex, allow_rip=True)
                reg = ((modrm >> 3) & 7) | ((rex & 4) << 1)
                instructions.append(Instruction(pc, code[pc:end], 'lea', reg=reg,
                                                amount=64 if rex & 8 else 32, memory=addr))
                pc = end
                continue
        specialized = decode_extended_memory(code, pc)
        if specialized:
            instructions.append(specialized)
            pc += len(specialized.raw)
            continue
        for size in range(3, 7):
            raw = code[pc:pc + size]
            if len(raw) != size: continue
            try:
                vector = decode_simd(raw + b'\xc3')
            except ValueError:
                continue
            if len(vector) == 1 and vector[0].op not in FP_IDS:
                instructions.append(Instruction(pc, raw, 'simd'))
                pc += size
                break
        if pc != start: continue
        found = False
        for size in range(2, MAX_ENCODING_BYTES + 1):
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
                memory = decode_memory(raw + b'\xc3', allow_rip=real)
            except ValueError:
                continue
            if len(memory) == 1 and memory[0].op != 'gpr':
                instructions.append(Instruction(pc, raw, 'memory', memory=memory[0]))
                pc += size
                found = True
                break
        if not found: raise ValueError(f'unsupported stack instruction at {start:#x}')
    if real and instructions and instructions[-1].op == 'ud2':
        return instructions
    raise ValueError('missing final RET')


def decode_extended_memory(code, pc):
    """Reuse the scalar MOV address decoder without rewriting guest state."""
    start = pc
    prefix = code[pc]
    if prefix in (0x66, 0xf3):
        pc += 1
        rex = code[pc] if pc < len(code) and 0x40 <= code[pc] <= 0x4f else 0
        pc += bool(rex)
        opcode = code[pc:pc + 2]
        if rex & 8 or opcode not in (b'\x0f\x6f', b'\x0f\x7f'):
            return None
        operation = 'vector_load' if opcode[-1] == 0x6f else 'vector_store'
        modrm = pc + 2
        alignment = 16 if prefix == 0x66 else 1
    else:
        rex = prefix if 0x40 <= prefix <= 0x4f else 0
        pc += bool(rex)
        if not rex & 8 or code[pc:pc + 1] != b'\x87':
            return None
        operation, modrm, alignment = 'exchange', pc + 1, 8
    if modrm >= len(code) or code[modrm] >> 6 == 3:
        return None
    for end in range(modrm + 1, min(len(code), modrm + 6) + 1):
        fake = bytes((0x48 | (rex & 7), 0x8b)) + code[modrm:end] + b'\xc3'
        try:
            operand, = decode_memory(fake)
        except ValueError:
            continue
        return Instruction(start, code[start:end], operation, reg=operand.reg,
                           amount=alignment, memory=operand)
    raise ValueError('unsupported vector/atomic memory operand')


def analyze(specification, *, real=False, image_limit=0x10000):
    functions = assemble(specification)
    if not 1 <= len(functions) <= 128: raise ValueError('expected 1..128 known functions')
    decoded, addresses = {}, {}
    for name, function in functions.items():
        if not name.isidentifier() or not name.isascii(): raise ValueError('invalid function name')
        address = function['address']
        if type(address) is not int or address < 0 or address + len(function['code']) > image_limit:
            raise ValueError('function outside bounded code image')
        if address in addresses: raise ValueError('duplicate function address')
        addresses[address] = name
        decoded[name] = decode(function['code'], real=real)
    spans = sorted((f['address'], f['address'] + len(f['code'])) for f in functions.values())
    if any(b[0] < a[1] for a, b in zip(spans, spans[1:])): raise ValueError('overlapping functions')
    calls = {}
    edges = {}
    for name, instructions in decoded.items():
        calls[name] = {}
        edges[name] = []
        boundaries = {insn.pc for insn in instructions}
        indirect = specification[name].get('indirect_targets', {})
        callbacks = specification[name].get('host_callbacks', {})
        if not isinstance(indirect, dict) or not isinstance(callbacks, dict):
            raise ValueError('call-site metadata must be an offset map')
        imports = specification[name].get('host_imports', {})
        if not isinstance(imports, dict) or (imports and not real):
            raise ValueError('host imports require the real module contract')
        used_indirect, used_callbacks, used_imports = set(), set(), set()
        for insn in instructions:
            key = str(insn.pc)
            if insn.op == 'branch' and insn.target not in boundaries:
                raise ValueError('branch must target an instruction boundary in its function')
            if insn.op == 'indirect':
                targets = indirect.get(key)
                if (not isinstance(targets, list) or not targets or
                        any(not isinstance(x, str) or x not in functions for x in targets) or
                        len(set(targets)) != len(targets)):
                    raise ValueError('indirect CALL needs a unique, registered target set')
                used_indirect.add(key)
                edges[name].append(tuple(targets))
            if insn.op == 'call':
                offset = functions[name]['address'] + insn.target
                if key in imports:
                    if type(imports[key]) is not int or imports[key] != offset or not 0 <= offset < image_limit:
                        raise ValueError('invalid host import target at CALL')
                    used_imports.add(key)
                elif offset == HOST_IMPORT and key in callbacks:
                    target = callbacks[key]
                    if not isinstance(target, str) or target not in functions:
                        raise ValueError('callback must target a registered entry')
                    used_callbacks.add(key)
                    edges[name].append((target,))
                else:
                    if offset not in addresses: raise ValueError('CALL must target a registered function entry')
                    calls[name][insn.pc] = addresses[offset]
                    edges[name].append((addresses[offset],))
        if used_indirect != set(indirect) or used_callbacks != set(callbacks) or used_imports != set(imports):
            raise ValueError('unused indirect CALL or callback metadata')
    complete, visiting, costs, depths = set(), set(), {}, {}

    def visit(name):
        if name in visiting: raise ValueError('recursive call graph outside bounded contract')
        if name in complete: return
        visiting.add(name)
        cost, depth = len(decoded[name]), 1
        for options in edges[name]:
            for callee in options: visit(callee)
            cost += max(costs[callee] for callee in options)
            depth = max(depth, 1 + max(depths[callee] for callee in options))
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
define i1 @ss_access(ptr %state, ptr %map, i64 %address, i64 %right, i64 %pc, i64 %width) {
 %bp = getelementptr i8, ptr %map, i64 8
 %np = getelementptr i8, ptr %map, i64 16
 %rp = getelementptr i8, ptr %map, i64 24
 %base = load i64, ptr %bp
 %size = load i64, ptr %np
 %rights = load i64, ptr %rp
 %offset = sub i64 %address, %base
 %above = icmp uge i64 %address, %base
 %enough = icmp uge i64 %size, %width
 %last = sub i64 %size, %width
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
 %allowed = icmp eq i64 %present, %right
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
 %ok = call i1 @ss_access(ptr %state, ptr %map, i64 %address, i64 1, i64 %pc, i64 8)
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
 %ok = call i1 @ss_access(ptr %state, ptr %map, i64 %address, i64 2, i64 %pc, i64 8)
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


def lift(specification, *, mapped=False, real=False, image_limit=0x10000, root_return=ROOT_RETURN):
    if real and not mapped:
        raise ValueError('real module requires checked region table')
    if real and not CODE_BASE + image_limit <= root_return <= MASK64:
        raise ValueError('root return overlaps real module image')
    functions, decoded, calls, costs = analyze(specification, real=real, image_limit=image_limit)
    module = [DECLARATIONS, support_ir()]
    if any(function.get('host_imports') for function in specification.values()):
        module.append('declare void @bb_state_host_import(ptr, ptr, i64)')
    if mapped:
        module += ['declare i32 @bb_regions_prepare(ptr, ptr)',
                   'declare ptr @bb_regions_select(ptr, ptr, i64, i32)']
    if any(insn.op == 'simd' for body in decoded.values() for insn in body):
        module.append(simd_declarations())
    if any(function.get('host_callbacks') for function in specification.values()):
        module.append('declare void @bb_state_host_callback(ptr, ptr, ptr, i64, ptr, ptr)')
    for name, instructions in decoded.items():
        lines = [f'define void @ss_{name}(ptr %state, ptr %data, ptr %stack, i64 %expected, ptr %budget) {{', 'entry:']
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

        flagptr = emit(f'getelementptr i8, ptr %state, i64 {OFFSETS["rflags"]}')

        def condition(cc):
            flags = emit(f'load i64, ptr {flagptr}, align 1')

            def bit(n):
                masked = emit(f'and i64 {flags}, {1 << n}')
                return emit(f'icmp ne i64 {masked}, 0')

            kind = cc >> 1
            if kind < 3:
                result = bit((11, 0, 6)[kind])
            elif kind == 3:
                result = emit(f'or i1 {bit(0)}, {bit(6)}')
            elif kind < 6:
                result = bit((7, 2)[kind - 4])
            else:
                result = emit(f'xor i1 {bit(7)}, {bit(11)}')
                if kind == 7:
                    result = emit(f'or i1 {bit(6)}, {result}')
            return emit(f'xor i1 {result}, true') if cc & 1 else result

        def compute_address(memory, next_pc):
            address = str(memory.displacement + (next_pc if memory.rip_relative else 0))
            if memory.base is not None:
                address = emit(f'add i64 {read(memory.base)}, {memory.displacement}')
            if memory.index is not None:
                scaled = emit(f'mul i64 {read(memory.index)}, {memory.scale}')
                address = emit(f'add i64 {address}, {scaled}')
            return address

        def locate(memory, next_pc):
            address = compute_address(memory, next_pc)
            if mapped:
                chosen = emit(f'call ptr @bb_regions_select(ptr %data, ptr %stack, i64 {address}, i32 {int(memory.base in (4, 5))})')
            else:
                chosen = emit(f'call ptr @ss_select(ptr %data, ptr %stack, i64 {address}, i1 {"true" if memory.base in (4, 5) else "false"})')
            return address, chosen

        lines.append('  br label %guest0')
        for insn in instructions:
            offset = functions[name]['address'] + insn.pc
            pc, next_pc = CODE_BASE + offset, CODE_BASE + offset + len(insn.raw)
            lines += [f'guest{insn.pc}:', f'  store i64 {pc}, ptr {rip}, align 1']
            remaining = emit('load i32, ptr %budget, align 4')
            exhausted = emit(f'icmp eq i32 {remaining}, 0')
            lines += [f'  br i1 {exhausted}, label %exhausted, label %step{insn.pc}', f'step{insn.pc}:']
            left = emit(f'sub i32 {remaining}, 1')
            lines.append(f'  store i32 {left}, ptr %budget, align 4')
            if insn.op == 'branch':
                if insn.amount < 0:
                    lines.append(f'  br label %guest{insn.target}')
                else:
                    predicate = condition(insn.amount)
                    lines.append(f'  br i1 {predicate}, label %guest{insn.target}, label %guest{insn.pc + len(insn.raw)}')
                continue
            if insn.op in ('gpr', 'adjust'):
                helper = f'ss_{name}_scalar_{insn.pc}'
                module.append(lift_gpr(insn.raw + b'\xc3', helper) if insn.op == 'gpr'
                              else lift_instructions([scalar_for_adjust(insn)], helper))
                lines.append(f'  call void @{helper}(ptr %state)')
            elif insn.op == 'lea':
                value = compute_address(insn.memory, next_pc)
                if insn.amount == 32:
                    low = emit(f'trunc i64 {value} to i32')
                    value = emit(f'zext i32 {low} to i64')
                write(insn.reg, value)
            elif insn.op == 'memory':
                _, chosen = locate(insn.memory, next_pc)
                helper = f'ss_{name}_memory_{insn.pc}'
                module.append(lift_memory(insn.raw + b'\xc3', helper, max_bytes=1048576 if mapped else STACK_BYTES, allow_rip=real))
                lines.append(f'  call void @{helper}(ptr %state, ptr {chosen})')
                value = emit(f'load i32, ptr {status}, align 1')
                good = emit(f'icmp eq i32 {value}, 0')
                label = f'memory_ok{serial}'
                lines.extend([f'  br i1 {good}, label %{label}, label %memory_fault{insn.pc}', f'memory_fault{insn.pc}:'])
                fault = emit(f'getelementptr i8, ptr {chosen}, i64 40')
                lines += [f'  store i64 {offset}, ptr {fault}', '  ret void', f'{label}:']
            elif insn.op == 'simd':
                helper = f'ss_{name}_simd_{insn.pc}'
                module.append(lift_simd(insn.raw + b'\xc3', helper, integer_only=True))
                lines.append(f'  call void @{helper}(ptr %state)')
            elif insn.op in ('vector_load', 'vector_store', 'exchange'):
                address, chosen = locate(insn.memory, next_pc)
                atomic = insn.op == 'exchange'
                width = 8 if atomic else 16
                right = 3 if atomic else 1 if insn.op == 'vector_load' else 2
                ok = emit(f'call i1 @ss_access(ptr %state, ptr {chosen}, i64 {address}, i64 {right}, i64 {offset}, i64 {width})')
                lines += [f'  br i1 {ok}, label %mapped{insn.pc}, label %halt', f'mapped{insn.pc}:']
                baseptr = emit(f'getelementptr i8, ptr {chosen}, i64 8')
                base = emit(f'load i64, ptr {baseptr}')
                buffer = emit(f'load ptr, ptr {chosen}')
                delta = emit(f'sub i64 {address}, {base}')
                host = emit(f'getelementptr i8, ptr {buffer}, i64 {delta}')
                if insn.amount > 1:
                    bits = address
                    if atomic:
                        # LLVM's atomic requires aligned host storage as well.
                        hostbits = emit(f'ptrtoint ptr {host} to i64')
                        bits = emit(f'or i64 {address}, {hostbits}')
                    low = emit(f'and i64 {bits}, {insn.amount - 1}')
                    aligned = emit(f'icmp eq i64 {low}, 0')
                    lines += [f'  br i1 {aligned}, label %aligned{insn.pc}, label %misaligned{insn.pc}',
                              f'misaligned{insn.pc}:', f'  store i32 8, ptr {status}, align 1']
                    fault_address = emit(f'getelementptr i8, ptr {chosen}, i64 32')
                    fault_offset = emit(f'getelementptr i8, ptr {chosen}, i64 40')
                    lines += [f'  store i64 {address}, ptr {fault_address}', f'  store i64 {offset}, ptr {fault_offset}',
                              '  ret void', f'aligned{insn.pc}:']
                if atomic:
                    old = emit(f'atomicrmw xchg ptr {host}, i64 {read(insn.reg)} seq_cst, align 8')
                    write(insn.reg, old)
                else:
                    vector = emit(f'getelementptr i8, ptr %state, i64 {xmm_offset(insn.reg)}')
                    src, dst = (host, vector) if insn.op == 'vector_load' else (vector, host)
                    value = emit(f'load i128, ptr {src}, align 1')
                    lines.append(f'  store i128 {value}, ptr {dst}, align 1')
            elif insn.op == 'fence':
                lines.append('  fence seq_cst')
            elif insn.op == 'ud2':
                lines += [f'  store i32 9, ptr {status}, align 1', '  ret void']
                continue
            elif insn.op in ('push', 'call', 'indirect'):
                if insn.op == 'indirect':
                    if insn.memory is None:
                        target = read(insn.reg)
                    else:
                        operand, chosen = locate(insn.memory, next_pc)
                        target = emit(f'call i64 @ss_read(ptr %state, ptr {chosen}, i64 {operand}, i64 {offset})')
                        check()
                    options = specification[name]['indirect_targets'][str(insn.pc)]
                    destination = 'null'
                    for callee in options:
                        match = emit(f'icmp eq i64 {target}, {CODE_BASE + functions[callee]["address"]}')
                        destination = emit(f'select i1 {match}, ptr @ss_{callee}, ptr {destination}')
                    valid = emit(f'icmp ne ptr {destination}, null')
                    lines += [f'  br i1 {valid}, label %resolved{insn.pc}, label %target_bad{insn.pc}',
                              f'target_bad{insn.pc}:', f'  store i32 5, ptr {status}, align 1']
                    address_field = emit('getelementptr i8, ptr %stack, i64 32')
                    offset_field = emit('getelementptr i8, ptr %stack, i64 40')
                    lines += [f'  store i64 {target}, ptr {address_field}', f'  store i64 {offset}, ptr {offset_field}',
                              '  ret void', f'resolved{insn.pc}:']
                sp = read(4)
                address = emit(f'sub i64 {sp}, 8')
                value = read(insn.reg) if insn.op == 'push' else str(next_pc)
                lines.append(f'  call void @ss_write(ptr %state, ptr %stack, i64 {address}, i64 {value}, i64 {offset})')
                check()
                write(4, address)
                if insn.op != 'push':
                    arguments = f'ptr %state, ptr %data, ptr %stack, i64 {next_pc}, ptr %budget'
                    callback = specification[name].get('host_callbacks', {}).get(str(insn.pc))
                    host_import = specification[name].get('host_imports', {}).get(str(insn.pc))
                    if host_import is not None:
                        lines.append(f'  call void @bb_state_host_import(ptr %state, ptr %data, i64 {host_import})')
                        check()
                        returned = emit(f'call i64 @ss_read(ptr %state, ptr %stack, i64 {address}, i64 {offset})')
                        check()
                        matches = emit(f'icmp eq i64 {returned}, {next_pc}')
                        lines += [f'  br i1 {matches}, label %import_return{insn.pc}, label %bad_import_return{insn.pc}',
                                  f'bad_import_return{insn.pc}:', f'  store i32 4, ptr {status}, align 1']
                        fault_address = emit('getelementptr i8, ptr %stack, i64 32')
                        fault_offset = emit('getelementptr i8, ptr %stack, i64 40')
                        lines += [f'  store i64 {returned}, ptr {fault_address}', f'  store i64 {offset}, ptr {fault_offset}',
                                  '  ret void', f'import_return{insn.pc}:']
                        write(4, sp)
                    elif callback:
                        lines.append(f'  call void @bb_state_host_callback({arguments}, ptr @ss_{callback})')
                    else:
                        callee = destination if insn.op == 'indirect' else f'@ss_{calls[name][insn.pc]}'
                        lines.append(f'  call void {callee}({arguments})')
                    check()
            elif insn.op in ('pop', 'leave', 'ret'):
                address = read(5 if insn.op == 'leave' else 4)
                value = emit(f'call i64 @ss_read(ptr %state, ptr %stack, i64 {address}, i64 {offset})')
                check()
                if insn.op == 'ret':
                    expected = emit(f'icmp eq i64 {value}, %expected')
                    lines += [f'  br i1 {expected}, label %return_ok{insn.pc}, label %return_bad{insn.pc}', f'return_bad{insn.pc}:',
                              f'  store i32 4, ptr {status}, align 1']
                    bad_address = emit('getelementptr i8, ptr %stack, i64 32')
                    bad_pc = emit('getelementptr i8, ptr %stack, i64 40')
                    lines += [f'  store i64 {value}, ptr {bad_address}', f'  store i64 {offset}, ptr {bad_pc}',
                              '  ret void', f'return_ok{insn.pc}:']
                    advanced = emit(f'add i64 {address}, 8')
                    write(4, advanced)
                    lines += [f'  store i64 {value}, ptr {rip}, align 1', '  ret void']
                else:
                    advanced = emit(f'add i64 {address}, 8')
                    write(4, value if insn.op == 'pop' and insn.reg == 4 else advanced)
                    if insn.op == 'leave': write(5, value)
                    elif insn.reg != 4: write(insn.reg, value)
            if insn.op != 'ret': lines.append(f'  br label %guest{insn.pc + len(insn.raw)}')
        lines += ['exhausted:', f'  store i32 6, ptr {status}, align 1', '  ret void',
                  'halt:', '  ret void', '}']
        module.append('\n'.join(lines))
        if mapped:
            module.append(f"""define void @entry_{name}(ptr %state, ptr %table, ptr %stack) {{
entry:
  %status = getelementptr i8, ptr %state, i64 {OFFSETS['status']}
  %validated = call i32 @bb_regions_prepare(ptr %table, ptr %stack)
  %valid = icmp ne i32 %validated, 0
  br i1 %valid, label %body, label %invalid
invalid:
  store i32 2, ptr %status, align 1
  ret void
body:
  store i32 0, ptr %status, align 1
  %budget = alloca i32, align 4
  store i32 {STEP_LIMIT}, ptr %budget, align 4
  call void @ss_{name}(ptr %state, ptr %table, ptr %stack, i64 {root_return}, ptr %budget)
  ret void
}}""")
            continue
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
                  ' %budget = alloca i32, align 4', f' store i32 {STEP_LIMIT}, ptr %budget, align 4',
                  f' call void @ss_{name}(ptr %state, ptr %data, ptr %stack, i64 {root_return}, ptr %budget)', ' ret void', '}']
        module.append('\n'.join(entry))
    return '\n\n'.join(module), functions, decoded, calls, costs
