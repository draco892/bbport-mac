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


@dataclass(frozen=True)
class Instruction:
    op: str
    dst: int
    src: int
    width: int
    condition: int = 0
    immediate: int | None = None


def decode(code):
    instructions, offset = [], 0
    while offset < len(code):
        if code[offset] == 0xc3:
            if not instructions or offset != len(code) - 1:
                raise ValueError('RET must end a nonempty fixture')
            return instructions
        rex = 0
        if 0x40 <= code[offset] <= 0x4f:
            rex = code[offset]
            if rex & 2:
                raise ValueError('REX.X outside the register-only contract')
            offset += 1
        if offset >= len(code):
            raise ValueError('truncated opcode')
        opcode = code[offset]
        offset += 1
        condition = None
        if opcode == 0x0f:
            if offset >= len(code) or not 0x40 <= code[offset] <= 0x4f:
                raise ValueError('only CMOVcc two-byte opcodes are supported')
            condition = code[offset] - 0x40
            offset += 1
        if offset >= len(code):
            raise ValueError('missing ModR/M')
        modrm = code[offset]
        offset += 1
        if modrm >> 6 != 3:
            raise ValueError('only GPR register operands are supported')
        reg = ((modrm >> 3) & 7) | ((rex & 4) << 1)
        rm = (modrm & 7) | ((rex & 1) << 3)
        width = 64 if rex & 8 else 32
        if condition is not None:
            insn = Instruction('cmov', reg, rm, width, condition)
        elif opcode == 0xff and not rex & 4 and (modrm >> 3) & 7 in (0, 1):
            insn = Instruction('inc' if (modrm >> 3) & 7 == 0 else 'dec', rm, rm, width)
        elif opcode in BINARY:
            insn = Instruction(BINARY[opcode], rm, reg, width)
        else:
            raise ValueError('unsupported opcode/extension')
        instructions.append(insn)
    raise ValueError('missing final RET')


def defined_flags(code):
    """Final defined arithmetic bits; AF is undefined only after logical ops."""
    mask = ARITHMETIC_FLAGS
    for insn in decode(code):
        if insn.op in ('and', 'or', 'xor', 'test'):
            mask = ARITHMETIC_FLAGS & ~0x10
        elif insn.op not in ('mov', 'cmov'):
            mask = ARITHMETIC_FLAGS
    return mask


def lift(code, name):
    return lift_instructions(decode(code), name)


def lift_instructions(instructions, name):
    """Lower validated scalar IR; stack mode supplies ADD/SUB immediate operands."""
    if not name.isascii() or not name.isidentifier():
        raise ValueError('invalid function name')
    if not instructions:
        raise ValueError('empty scalar IR')
    for insn in instructions:
        if (insn.op not in {*BINARY.values(), 'cmov', 'inc', 'dec'} or insn.width not in (32, 64)
                or not 0 <= insn.dst < 16 or not 0 <= insn.src < 16 or not 0 <= insn.condition < 16
                or (insn.immediate is not None and
                    (type(insn.immediate) is not int or insn.op not in ('add', 'sub')))):
            raise ValueError('unsupported scalar IR contract')
    lines = [f'define void @{name}(ptr %state) {{', 'entry:']
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

    for insn in instructions:
        w, op = insn.width, insn.op
        ty = f'i{w}'
        a, b = registers[insn.dst], registers[insn.src]
        if w == 32:
            a, b = emit(f'trunc i64 {a} to i32'), emit(f'trunc i64 {b} to i32')
        if insn.immediate is not None:
            b = str(insn.immediate & ((1 << w) - 1))
        if op == 'mov':
            result = b
        elif op == 'cmov':
            result = emit(f'select i1 {condition(insn.condition)}, {ty} {b}, {ty} {a}')
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
            zero = emit(f'icmp eq {ty} {result}, 0')
            sign = emit(f'icmp slt {ty} {result}, 0')
            low = emit(f'trunc {ty} {result} to i8')
            population = emit(f'call i8 @llvm.ctpop.i8(i8 {low})')
            odd = emit(f'and i8 {population}, 1')
            parity = emit(f'icmp eq i8 {odd}, 0')
            new_flags = emit(f'and i64 {flags}, {-1 ^ ARITHMETIC_FLAGS}')
            for value, bit in ((carry, 0), (parity, 2), (auxiliary, 4), (zero, 6), (sign, 7), (overflow, 11)):
                widened = emit(f'zext i1 {value} to i64')
                positioned = emit(f'shl i64 {widened}, {bit}') if bit else widened
                new_flags = emit(f'or i64 {new_flags}, {positioned}')
            flags = new_flags
        if op not in ('cmp', 'test'):
            registers[insn.dst] = emit(f'zext i32 {result} to i64') if w == 32 else result
    lines.extend(f'  store i64 {value}, ptr {pointer}, align 1' for value, pointer in zip(registers, pointers))
    lines += [f'  store i64 {flags}, ptr {flagptr}, align 1',
              f'  %status = getelementptr i8, ptr %state, i64 {STATUS_OFFSET}',
              '  store i32 0, ptr %status, align 1', '  ret void', '}']
    return '\n'.join(lines)


DECLARATIONS = 'declare i8 @llvm.ctpop.i8(i8)\n'
