"""Restricted synthetic memory/control-flow experiment for issue #9.

RDI is an immutable base pointer to a 64-byte test region, RSI a scalar input.
Only whitelisted encodings, statically bounded accesses and forward edges are
accepted. This is not a decoder for arbitrary game code or a guest address mapper.
"""
from dataclasses import dataclass

MEMORY_BYTES = 64
PREDICATES = {0x74: 'eq', 0x75: 'ne', 0x72: 'ult', 0x73: 'uge', 0x76: 'ule',
              0x77: 'ugt', 0x7c: 'slt', 0x7d: 'sge', 0x7e: 'sle', 0x7f: 'sgt'}


@dataclass(frozen=True)
class Instruction:
    pc: int
    size: int
    op: str
    width: int = 64
    source: str = 'rax'
    displacement: int = 0
    target: int = 0
    condition: int = 0


def decode(code, extra_decode=None):
    """Decode the whole fixture; reject unsupported or truncated encodings."""
    if not code or len(code) > 4096:
        raise ValueError('expected 1..4096 bytes of synthetic code')
    instructions = []
    pc = 0
    registers = {
        b'\x48\x89\xf0': ('mov', 64, 'b'), b'\x89\xf0': ('mov', 32, 'b'),
        b'\x48\x39\xf0': ('cmp', 64, 'rax'), b'\x39\xf0': ('cmp', 32, 'rax'),
        b'\x48\x85\xc0': ('test', 64, 'rax'), b'\x85\xc0': ('test', 32, 'rax'),
        b'\x48\x85\xf6': ('test', 64, 'b'), b'\x85\xf6': ('test', 32, 'b'),
    }
    for prefix, width in ((b'\x48', 64), (b'', 32)):
        for opcode, op in ((1, 'add'), (0x29, 'sub'), (0x31, 'xor')):
            registers[prefix + bytes((opcode, 0xf0))] = (op, width, 'rax')
    memory = [
        (b'\x48\x8b', 'load', 64), (b'\x8b', 'load', 32),
        (b'\x0f\xb6', 'load', 8), (b'\x0f\xb7', 'load', 16),
        (b'\x48\x0f\xbe', 'signed_load', 8),
        (b'\x48\x0f\xbf', 'signed_load', 16), (b'\x48\x63', 'signed_load', 32),
        (b'\x48\x89', 'store', 64), (b'\x89', 'store', 32),
        (b'\x66\x89', 'store', 16), (b'\x88', 'store', 8),
    ]
    while pc < len(code):
        current = extra_decode(code, pc) if extra_decode else None
        if current is None:
            for encoding, (op, width, source) in registers.items():
                if code.startswith(encoding, pc):
                    current = Instruction(pc, len(encoding), op, width, source)
                    break
        if current is None:
            for encoding, op, width in memory:
                if not code.startswith(encoding, pc):
                    continue
                modrm_at = pc + len(encoding)
                if modrm_at >= len(code):
                    raise ValueError(f'truncated memory operand at {pc:#x}')
                modrm = code[modrm_at]
                # [rdi] and [rdi+disp8], with RAX or (for stores) RSI.
                allowed = (7, 0x47, 0x37, 0x77) if op == 'store' and width != 8 else (7, 0x47)
                if modrm not in allowed:
                    continue
                size = len(encoding) + 1
                displacement = 0
                if modrm & 0x40:
                    if pc + size >= len(code):
                        raise ValueError(f'truncated displacement at {pc:#x}')
                    displacement = int.from_bytes(code[pc + size:pc + size + 1], 'little', signed=True)
                    size += 1
                if not 0 <= displacement <= MEMORY_BYTES - width // 8:
                    raise ValueError(f'memory access outside {MEMORY_BYTES}-byte region at {pc:#x}')
                source = 'b' if op == 'store' and modrm in (0x37, 0x77) else 'rax'
                current = Instruction(pc, size, op, width, source, displacement)
                break
        if current is None and (code[pc] in PREDICATES or code[pc] == 0xeb):
            if pc + 1 >= len(code):
                raise ValueError(f'truncated branch at {pc:#x}')
            target = pc + 2 + int.from_bytes(code[pc + 1:pc + 2], 'little', signed=True)
            if target < pc + 2:
                raise ValueError(f'backward branch at {pc:#x}')
            current = Instruction(pc, 2, 'jump' if code[pc] == 0xeb else 'branch',
                                  target=target, condition=code[pc])
        if current is None and code[pc] == 0xc3:
            current = Instruction(pc, 1, 'ret')
        if current is None:
            raise ValueError(f'unsupported encoding at {pc:#x}: {code[pc:].hex()}')
        instructions.append(current)
        pc += current.size
    return instructions


def successors(ins):
    if ins.op == 'ret':
        return ()
    if ins.op == 'jump':
        return (ins.target,)
    if ins.op == 'branch':
        return (ins.pc + ins.size, ins.target)
    return (ins.pc + ins.size,)


def validate(instructions):
    """Forward data flow: RAX/flags must be defined on every incoming path."""
    boundaries = {ins.pc for ins in instructions}
    states = {0: (False, None)}
    for ins in instructions:
        if ins.pc not in states:
            raise ValueError(f'unreachable instruction at {ins.pc:#x}')
        initialized, flags = states[ins.pc]
        needs_rax = ins.op in ('ret', 'cmp', 'add', 'sub', 'xor') or (
            ins.op in ('store', 'test') and ins.source == 'rax')
        if needs_rax and not initialized:
            raise ValueError(f'undefined RAX at {ins.pc:#x}')
        if ins.op == 'branch':
            if flags is None or (flags[0] == 'test' and ins.condition not in (0x74, 0x75)):
                raise ValueError(f'unsupported or undefined branch flags at {ins.pc:#x}')
        if ins.op in ('load', 'signed_load', 'mov', 'add', 'sub', 'xor'):
            initialized = True
        if ins.op in ('add', 'sub', 'xor'):
            flags = None  # arithmetic flag consumers are outside this experiment
        if ins.op in ('cmp', 'test'):
            flags = (ins.op, ins.width)
        for target in successors(ins):
            if target not in boundaries:
                raise ValueError(f'edge from {ins.pc:#x} to non-instruction boundary {target:#x}')
            state = (initialized, flags)
            if target in states:
                old_init, old_flags = states[target]
                state = (old_init and initialized, flags if flags == old_flags else None)
            states[target] = state
    return states


def lift_memory(code, name):
    if not name.isidentifier() or not name.isascii():
        raise ValueError('invalid function name')
    instructions = decode(code)
    states = validate(instructions)
    lines = [f'define i64 @{name}(ptr %guest, i64 %b) {{', 'entry:',
             '  %rax.slot = alloca i64', '  %left.slot = alloca i64',
             '  %right.slot = alloca i64', '  br label %b0']
    serial = 0

    def emit(expression):
        nonlocal serial
        serial += 1
        result = f'%v{serial}'
        lines.append(f'  {result} = {expression}')
        return result

    def rax():
        return emit('load i64, ptr %rax.slot')

    def narrow(value, width):
        return value if width == 64 else emit(f'trunc i64 {value} to i{width}')

    def extend(value, width, signed=False):
        if width == 64:
            return value
        return emit(f'{"sext" if signed else "zext"} i{width} {value} to i64')

    for ins in instructions:
        lines.append(f'b{ins.pc}:')
        value = None
        if ins.op in ('load', 'signed_load', 'store'):
            address = emit(f'getelementptr i8, ptr %guest, i64 {ins.displacement}')
            if ins.op == 'store':
                stored = narrow('%b' if ins.source == 'b' else rax(), ins.width)
                lines.append(f'  store i{ins.width} {stored}, ptr {address}, align 1')
            else:
                loaded = emit(f'load i{ins.width}, ptr {address}, align 1')
                value = extend(loaded, ins.width, ins.op == 'signed_load')
        elif ins.op == 'mov':
            value = extend(narrow('%b', ins.width), ins.width)
        elif ins.op in ('add', 'sub', 'xor'):
            left, right = narrow(rax(), ins.width), narrow('%b', ins.width)
            value = extend(emit(f'{ins.op} i{ins.width} {left}, {right}'), ins.width)
        elif ins.op in ('cmp', 'test'):
            left = '%b' if ins.source == 'b' else rax()
            right = '%b' if ins.op == 'cmp' else '0'
            lines.extend([f'  store i64 {left}, ptr %left.slot',
                          f'  store i64 {right}, ptr %right.slot'])
        if value is not None:
            lines.append(f'  store i64 {value}, ptr %rax.slot')
        if ins.op == 'ret':
            lines.append(f'  ret i64 {rax()}')
        elif ins.op == 'branch':
            width = states[ins.pc][1][1]
            left = narrow(emit('load i64, ptr %left.slot'), width)
            right = narrow(emit('load i64, ptr %right.slot'), width)
            result = emit(f'icmp {PREDICATES[ins.condition]} i{width} {left}, {right}')
            lines.append(f'  br i1 {result}, label %b{ins.target}, label %b{ins.pc + ins.size}')
        elif ins.op == 'jump':
            lines.append(f'  br label %b{ins.target}')
        else:
            lines.append(f'  br label %b{ins.pc + ins.size}')
    lines.append('}')
    return '\n'.join(lines)
