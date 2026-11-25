"""Bounded 32/64-bit register arithmetic and status flags in CPU-state ABI v1.

No guest memory, dispatch, stack use or branches. RSP is an ordinary guest value.
Undefined AF after logical instructions is normalized to zero, never emulated.
"""
from dataclasses import dataclass
from cpu_state import OFFSETS, STATUS_OFFSET

ARITHMETIC_FLAGS = 0x8d5  # CF, PF, AF, ZF, SF, OF
BINARY = {0x01: 'add', 0x11: 'adc', 0x29: 'sub', 0x19: 'sbb',
          0x21: 'and', 0x09: 'or', 0x31: 'xor', 0x39: 'cmp',
          0x85: 'test', 0x89: 'mov'}
GROUP1 = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')
MAX_ENCODING_BYTES = 10
ACC_IMMEDIATE = {0x3c: 'cmp', 0x3d: 'cmp', 0xa8: 'test', 0xa9: 'test'}
SHIFT = {0: 'rol', 1: 'ror', 4: 'shl', 5: 'shr', 7: 'sar'}
ROTATE = ('rol', 'ror')
EXTEND = {0xb6: ('movzx', 8), 0xb7: ('movzx', 16),
          0xbe: ('movsx', 8), 0xbf: ('movsx', 16)}
MOVES = ('mov', 'cmov', 'movsx', 'movzx')


@dataclass(frozen=True)
class Instruction:
    op: str
    dst: int
    src: int
    width: int
    condition: int = 0
    immediate: int | None = None
    source_width: int = 0


def decode(code):
    instructions, offset = [], 0

    def read_immediate(size, *, signed=False):
        nonlocal offset
        end = offset + size
        if end > len(code):
            raise ValueError('truncated immediate')
        value = int.from_bytes(code[offset:end], 'little', signed=signed)
        offset = end
        return value

    while offset < len(code):
        if code[offset] == 0xc3:
            if not instructions or offset != len(code) - 1:
                raise ValueError('RET must end a nonempty fixture')
            return instructions
        word = code[offset] == 0x66
        if word: offset += 1
        rex = 0
        if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
            rex = code[offset]
            if rex & 2:
                raise ValueError('REX.X outside the register-only contract')
            offset += 1
        if offset >= len(code):
            raise ValueError('truncated opcode')
        opcode = code[offset]
        offset += 1
        if word and rex & 8:
            raise ValueError('conflicting operand widths')
        width = 64 if rex & 8 else 16 if word else 32
        if 0xb0 <= opcode <= 0xbf:
            reg = (opcode & 7) | ((rex & 1) << 3)
            if opcode < 0xb8:
                if word or rex & 8 or (not rex and reg >= 4):
                    raise ValueError('unsupported byte register encoding')
                width = 8
            value = read_immediate(width // 8)
            instructions.append(Instruction('mov', reg, reg, width, immediate=value))
            continue
        if opcode in ACC_IMMEDIATE:
            if opcode in (0x3c, 0xa8):
                if word or rex & 8: raise ValueError('unsupported byte prefix')
                width = 8
            value = read_immediate(min(width // 8, 4), signed=width == 64)
            instructions.append(Instruction(ACC_IMMEDIATE[opcode], 0, 0, width, immediate=value))
            continue
        condition = extension = None
        if opcode == 0x0f:
            if offset >= len(code):
                raise ValueError('truncated extended opcode')
            if 0x40 <= code[offset] <= 0x4f:
                condition = code[offset] - 0x40
            elif code[offset] in EXTEND:
                extension = EXTEND[code[offset]]
            else:
                raise ValueError('unsupported extended register opcode')
            offset += 1
        elif opcode == 0x63 and width == 64:
            extension = ('movsx', 32)
        if offset >= len(code):
            raise ValueError('missing ModR/M')
        modrm = code[offset]
        offset += 1
        if modrm >> 6 != 3:
            raise ValueError('only GPR register operands are supported')
        reg = ((modrm >> 3) & 7) | ((rex & 4) << 1)
        rm = (modrm & 7) | ((rex & 1) << 3)
        if extension:
            op, source = extension
            if source >= width or (source == 8 and not rex and rm >= 4):
                raise ValueError('unsupported extension operands')
            instructions.append(Instruction(op, reg, rm, width, source_width=source))
            continue
        if opcode in (0xc1, 0xd1, 0xd3):
            op = SHIFT.get(reg)
            if not op or width not in (32, 64):
                raise ValueError('unsupported shift/rotate form')
            count = None if opcode == 0xd3 else (1 if opcode == 0xd1 else read_immediate(1) & (width - 1))
            instructions.append(Instruction(op, rm, 1 if count is None else rm, width, immediate=count))
            continue
        if opcode in (0x80, 0x81, 0x83, 0xc6, 0xc7, 0xf6, 0xf7):
            extension = (modrm >> 3) & 7
            group1 = opcode in (0x80, 0x81, 0x83)
            if rex & 4 or (not group1 and extension != 0):
                raise ValueError('unsupported immediate opcode extension')
            if opcode in (0x80, 0xc6, 0xf6):
                if word or rex & 8 or (not rex and rm >= 4):
                    raise ValueError('unsupported byte register encoding')
                width = 8
            op = GROUP1[extension] if group1 else 'mov' if opcode in (0xc6, 0xc7) else 'test'
            size = 1 if opcode == 0x83 else min(width // 8, 4)
            value = read_immediate(size, signed=opcode == 0x83 or width == 64)
            instructions.append(Instruction(op, rm, rm, width, immediate=value))
            continue
        reversed_binary = opcode in (0x8a, 0x8b, 0x3a, 0x3b)
        if reversed_binary: opcode -= 2
        byte_opcode = opcode in (0x00, 0x10, 0x28, 0x18, 0x20, 0x08, 0x30, 0x38, 0x84, 0x88, 0xfe)
        if byte_opcode:
            if word or rex & 8 or (not rex and (rm >= 4 or (opcode != 0xfe and reg >= 4))):
                raise ValueError('unsupported byte register encoding')
            width = 8
            if opcode != 0xfe: opcode += 1
        if condition is not None:
            insn = Instruction('cmov', reg, rm, width, condition)
        elif opcode in (0xfe, 0xff) and not rex & 4 and (modrm >> 3) & 7 in (0, 1):
            insn = Instruction('inc' if (modrm >> 3) & 7 == 0 else 'dec', rm, rm, width)
        elif opcode in BINARY:
            dst, src = (reg, rm) if reversed_binary else (rm, reg)
            insn = Instruction(BINARY[opcode], dst, src, width)
        else:
            raise ValueError('unsupported opcode/extension')
        instructions.append(insn)
    raise ValueError('missing final RET')


def defined_flags(code, mask=ARITHMETIC_FLAGS):
    """Final architecturally defined arithmetic bits."""
    for insn in decode(code):
        if insn.op in SHIFT.values():
            if insn.immediate is None:
                mask &= ~0x800 if insn.op in ROTATE else ~0x810
                continue
            if not insn.immediate: continue
            if insn.op not in ROTATE:
                mask = ARITHMETIC_FLAGS & ~0x10
            mask = (mask | 0x801) if insn.immediate == 1 else ((mask | 1) & ~0x800)
        elif insn.op in ('and', 'or', 'xor', 'test'):
            mask = ARITHMETIC_FLAGS & ~0x10
        elif insn.op not in MOVES:
            mask = ARITHMETIC_FLAGS
    return mask


def lift(code, name):
    return lift_instructions(decode(code), name)


def lift_instructions(instructions, name, *, memory_operand=None):
    """Lower validated scalar IR with register and immediate operands."""
    if not name.isascii() or not name.isidentifier():
        raise ValueError('invalid function name')
    if not instructions:
        raise ValueError('empty scalar IR')
    if memory_operand is not None and (memory_operand not in ('dst', 'src') or len(instructions) != 1
                                       or instructions[0].op not in ('cmp', 'test')):
        raise ValueError('external memory operand requires a single comparison')
    for insn in instructions:
        if (insn.op not in {*BINARY.values(), *SHIFT.values(), *MOVES, 'inc', 'dec'}
                or insn.width not in (8, 16, 32, 64)
                or not 0 <= insn.dst < 16 or not 0 <= insn.src < 16 or not 0 <= insn.condition < 16
                or (insn.immediate is not None and
                    (type(insn.immediate) is not int or insn.op not in (*GROUP1, *SHIFT.values(), 'mov', 'test')))):
            raise ValueError('unsupported scalar IR contract')
        if insn.op in SHIFT.values() and (insn.width not in (32, 64) or
                (insn.immediate is None and insn.src != 1) or
                (insn.immediate is not None and not 0 <= insn.immediate < insn.width)):
            raise ValueError('invalid shift operand')
        if insn.op in ('movsx', 'movzx') and (insn.source_width not in (8, 16, 32)
                                              or insn.source_width >= insn.width):
            raise ValueError('invalid move extension width')
    extra = ', i64 %operand' if memory_operand else ''
    lines = [f'define void @{name}(ptr %state{extra}) {{', 'entry:']
    serial = 0

    def emit(expression):
        nonlocal serial
        serial += 1
        value = f'%v{serial}'
        lines.append(f'  {value} = {expression}')
        return value

    pointers = [emit(f'getelementptr i8, ptr %state, i64 {r * 8}') for r in range(16)]
    registers = [emit(f'load i64, ptr {p}, align 1') for p in pointers]
    flagptr = emit(f'getelementptr i8, ptr %state, i64 {OFFSETS["rflags"]}')
    flags = emit(f'load i64, ptr {flagptr}, align 1')

    def flag(bit):
        return emit(f'icmp ne i64 {emit(f"and i64 {flags}, {1 << bit}")}, 0')

    def condition(cc):
        # Paired condition codes differ only in their low (inversion) bit.
        kind = cc >> 1
        if kind == 0: result = flag(11)
        elif kind == 1: result = flag(0)
        elif kind == 2: result = flag(6)
        elif kind == 3: result = emit(f'or i1 {flag(0)}, {flag(6)}')
        elif kind == 4: result = flag(7)
        elif kind == 5: result = flag(2)
        else:
            result = emit(f'xor i1 {flag(7)}, {flag(11)}')
            if kind == 7:
                result = emit(f'or i1 {flag(6)}, {result}')
        return emit(f'xor i1 {result}, true') if cc & 1 else result

    def update_flags(updates):
        bits = sum(1 << bit for _, bit in updates)
        result = emit(f'and i64 {flags}, {-1 ^ bits}')
        for value, bit in updates:
            widened = emit(f'zext i1 {value} to i64')
            positioned = emit(f'shl i64 {widened}, {bit}') if bit else widened
            result = emit(f'or i64 {result}, {positioned}')
        return result

    def flags_zsp(value, width):
        ty = f'i{width}'
        zero = emit(f'icmp eq {ty} {value}, 0')
        sign = emit(f'icmp slt {ty} {value}, 0')
        low = value if width == 8 else emit(f'trunc {ty} {value} to i8')
        population = emit(f'call i8 @llvm.ctpop.i8(i8 {low})')
        odd = emit(f'and i8 {population}, 1')
        parity = emit(f'icmp eq i8 {odd}, 0')
        return (zero, 6), (sign, 7), (parity, 2)

    for insn in instructions:
        w, op = insn.width, insn.op
        ty = f'i{w}'
        a, b = registers[insn.dst], registers[insn.src]
        if memory_operand == 'dst': a = '%operand'
        if memory_operand == 'src': b = '%operand'
        if w != 64:
            a, b = emit(f'trunc i64 {a} to {ty}'), emit(f'trunc i64 {b} to {ty}')
        if insn.immediate is not None:
            b = str(insn.immediate & ((1 << w) - 1))
        if op == 'mov':
            result = b
        elif op in ('movsx', 'movzx'):
            source = f'i{insn.source_width}'
            narrow = emit(f'trunc {ty} {b} to {source}')
            extend = 'sext' if op == 'movsx' else 'zext'
            result = emit(f'{extend} {source} {narrow} to {ty}')
        elif op == 'cmov':
            result = emit(f'select i1 {condition(insn.condition)}, {ty} {b}, {ty} {a}')
        elif op in SHIFT.values():
            count = insn.immediate
            result = a
            if count is None:
                # All shift amounts must be in range even when the masked count is zero.
                count = emit(f'and {ty} {b}, {w - 1}')
                zero = emit(f'icmp eq {ty} {count}, 0')
                one = emit(f'icmp eq {ty} {count}, 1')
                back = emit(f'and {ty} {emit(f"sub {ty} 0, {count}")}, {w - 1}')
                prev = emit(f'and {ty} {emit(f"sub {ty} {count}, 1")}, {w - 1}')
            elif count:
                zero, one = 'false', 'true' if count == 1 else 'false'
                back, prev = w - count, count - 1
            if count != 0:
                def bit_at(value, bit):
                    shifted = emit(f'lshr {ty} {value}, {bit}')
                    return emit(f'trunc {ty} {shifted} to i1')

                if op in ROTATE:
                    left, right = (count, back) if op == 'rol' else (back, count)
                    high = emit(f'shl {ty} {a}, {left}')
                    low = emit(f'lshr {ty} {a}, {right}')
                    result = emit(f'or {ty} {high}, {low}')
                    carry = bit_at(result, 0 if op == 'rol' else w - 1)
                    first, second = (bit_at(result, w - 1), carry) if op == 'rol' else (carry, bit_at(result, w - 2))
                    overflow = emit(f'and i1 {one}, {emit(f"xor i1 {first}, {second}")}')
                    updated = update_flags(((carry, 0), (overflow, 11)))
                else:
                    shift = {'shl': 'shl', 'shr': 'lshr', 'sar': 'ashr'}[op]
                    result = emit(f'{shift} {ty} {a}, {count}')
                    carry = bit_at(a, back if op == 'shl' else prev)
                    overflow = 'false'
                    if op == 'shl':
                        overflow = emit(f'xor i1 {bit_at(result, w - 1)}, {carry}')
                    elif op == 'shr':
                        overflow = bit_at(a, w - 1)
                    overflow = emit(f'and i1 {one}, {overflow}')
                    updated = update_flags(((carry, 0), ('false', 4), (overflow, 11), *flags_zsp(result, w)))
                flags = emit(f'select i1 {zero}, i64 {flags}, i64 {updated}')
        else:
            if op in ('inc', 'dec'):
                b = '1'
            if op in ('and', 'or', 'xor', 'test'):
                result = emit(f'{"and" if op == "test" else op} {ty} {a}, {b}')
                carry, overflow, auxiliary = 'false', 'false', 'false'
            else:
                subtract = op in ('sub', 'sbb', 'cmp', 'dec')
                extended = f'i{w + 1}'
                aa = emit(f'zext {ty} {a} to {extended}')
                bb = emit(f'zext {ty} {b} to {extended}')
                if op in ('adc', 'sbb'):
                    incoming = emit(f'zext i1 {flag(0)} to {extended}')
                    bb = emit(f'add {extended} {bb}, {incoming}')
                total = emit(f'{"sub" if subtract else "add"} {extended} {aa}, {bb}')
                result = emit(f'trunc {extended} {total} to {ty}')
                if subtract:
                    carry = emit(f'icmp ult {extended} {aa}, {bb}')
                else:
                    high = emit(f'lshr {extended} {total}, {w}')
                    carry = emit(f'trunc {extended} {high} to i1')
                axb = emit(f'xor {ty} {a}, {b}')
                axr = emit(f'xor {ty} {a}, {result}')
                of_left = axb if subtract else emit(f'xor {ty} {axb}, -1')
                ov = emit(f'and {ty} {of_left}, {axr}')
                overflow = emit(f'icmp slt {ty} {ov}, 0')
                aux = emit(f'xor {ty} {axb}, {result}')
                auxiliary = emit(f'icmp ne {ty} {emit(f"and {ty} {aux}, 16")}, 0')
                if op in ('inc', 'dec'):
                    carry = flag(0)
            flags = update_flags(((carry, 0), (auxiliary, 4), (overflow, 11), *flags_zsp(result, w)))
        if op not in ('cmp', 'test'):
            if w != 64:
                result = emit(f'zext {ty} {result} to i64')
                if w < 32:
                    upper = emit(f'and i64 {registers[insn.dst]}, {-1 << w}')
                    result = emit(f'or i64 {upper}, {result}')
            registers[insn.dst] = result
    lines.extend(f'  store i64 {value}, ptr {pointer}, align 1' for value, pointer in zip(registers, pointers))
    lines += [f'  store i64 {flags}, ptr {flagptr}, align 1',
              f'  %status = getelementptr i8, ptr %state, i64 {STATUS_OFFSET}',
              '  store i32 0, ptr %status, align 1', '  ret void', '}']
    return '\n'.join(lines)


DECLARATIONS = 'declare i8 @llvm.ctpop.i8(i8)\n'
