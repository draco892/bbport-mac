"""Checked guest-memory accesses in CPU-state ABI v1, with scalar GPR sequences.

Straight-line bounded fixtures only; legacy forward-branch mode stays separate.
Every guest effective address is an i64 integer until bounds/permissions pass.
"""
from dataclasses import dataclass
from cpu_state import OFFSETS
from x86_address import decode_address
from gpr_lift import decode as decode_gpr, lift as lift_gpr, DECLARATIONS, MAX_ENCODING_BYTES

MEMORY_BYTES = 64
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Instruction:
    pc: int
    raw: bytes
    op: str
    reg: int = 0
    width: int = 0
    destination_width: int = 0
    base: int | None = None
    index: int | None = None
    scale: int = 1
    displacement: int = 0
    rip_relative: bool = False


def decode(code, *, allow_rip=False):
    if not code or len(code) > 4096:
        raise ValueError('expected 1..4096 bytes')
    result, offset = [], 0
    while offset < len(code):
        start = offset
        if code[offset] == 0xc3:
            if offset != len(code) - 1 or not any(i.op != 'gpr' for i in result):
                raise ValueError('final RET must terminate a fixture containing memory')
            return result
        # Reuse the verified scalar decoder, with exactly one instruction.
        found = False
        for size in range(2, MAX_ENCODING_BYTES + 1):
            candidate = code[offset:offset + size]
            if len(candidate) != size: continue
            try:
                scalar = decode_gpr(candidate + b'\xc3')
            except ValueError:
                continue
            if len(scalar) == 1:
                result.append(Instruction(start, candidate, 'gpr'))
                offset += size
                found = True
                break
        if found: continue
        word = code[offset] == 0x66
        if word: offset += 1
        rex = 0
        if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
            rex = code[offset]
            offset += 1
        if word and rex & 8:
            raise ValueError('noncanonical operand-size prefix combination')
        if offset >= len(code): raise ValueError('missing opcode')
        opcode = code[offset]
        offset += 1
        extension = None
        if opcode == 0x0f:
            if offset >= len(code): raise ValueError('truncated extended opcode')
            extension = code[offset]
            offset += 1
        destination_width = 64 if rex & 8 else 16 if word else 32
        if opcode in (0x8b, 0x89):
            op, width = ('load' if opcode == 0x8b else 'store'), destination_width
        elif opcode in (0x8a, 0x88) and not word and not rex & 8:
            op, width, destination_width = ('load' if opcode == 0x8a else 'store'), 8, 8
        elif opcode == 0x0f and extension in (0xb6, 0xb7, 0xbe, 0xbf) and not word:
            op = 'signed_load' if extension in (0xbe, 0xbf) else 'zero_load'
            width = 8 if extension in (0xb6, 0xbe) else 16
        elif opcode == 0x63 and rex & 8 and not word:
            op, width = 'signed_load', 32
        else:
            raise ValueError(f'unsupported memory encoding at {start:#x}')
        if offset >= len(code): raise ValueError('missing ModR/M')
        modrm = code[offset]
        offset += 1
        if modrm >> 6 == 3: raise ValueError('unsupported register form')
        reg = ((modrm >> 3) & 7) | ((rex & 4) << 1)
        if width == destination_width == 8 and not rex and reg >= 4:
            raise ValueError('AH/CH/DH/BH are outside this contract')
        address, offset = decode_address(code, offset, modrm, rex, allow_rip=allow_rip)
        raw = code[start:offset]
        if len(raw) > 15: raise ValueError('instruction exceeds x86 size limit')
        result.append(Instruction(start, raw, op, reg, width, destination_width,
                                  address.base, address.index, address.scale, address.displacement,
                                  address.rip_relative))
    raise ValueError('missing final RET')


def effective_address(insn, registers, *, rip=None):
    address = 0
    if insn.rip_relative:
        if rip is None:
            raise ValueError('RIP-relative operand requires the guest entry address')
        address = rip + insn.pc + len(insn.raw)
    if insn.base is not None: address += registers[insn.base]
    if insn.index is not None: address += registers[insn.index] * insn.scale
    return (address + insn.displacement) & MASK64


def lift(code, name, *, max_bytes=MEMORY_BYTES, allow_rip=False):
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1048576:
        raise ValueError('bounded region limit must be 1..1048576 bytes')
    if not name.isascii() or not name.isidentifier(): raise ValueError('invalid function name')
    instructions = decode(code, allow_rip=allow_rip)
    helpers = []
    lines = [f'define void @{name}(ptr %state, ptr %mapping) {{', 'entry:']
    serial = 0

    def emit(expression):
        nonlocal serial
        serial += 1
        result = f'%m{serial}'
        lines.append(f'  {result} = {expression}')
        return result

    status = emit(f'getelementptr i8, ptr %state, i64 {OFFSETS["status"]}')
    fields = [emit(f'getelementptr i8, ptr %mapping, i64 {i * 8}') for i in range(6)]
    data = emit(f'load ptr, ptr {fields[0]}, align 8')
    base, size, permissions = [emit(f'load i64, ptr {fields[i]}, align 8') for i in (1, 2, 3)]
    lines += [f'  store i64 0, ptr {fields[4]}, align 8', f'  store i64 0, ptr {fields[5]}, align 8']
    limited = emit(f'icmp ule i64 {size}, {max_bytes}')
    end_limit = emit(f'sub i64 -1, {size}')
    no_wrap = emit(f'icmp ule i64 {base}, {end_limit}')
    known_permissions = emit(f'icmp ule i64 {permissions}, 3')
    not_null = emit(f'icmp ne ptr {data}, null')
    empty = emit(f'icmp eq i64 {size}, 0')
    valid_data = emit(f'or i1 {not_null}, {empty}')
    valid = emit(f'and i1 {limited}, {no_wrap}')
    valid = emit(f'and i1 {valid}, {known_permissions}')
    valid = emit(f'and i1 {valid}, {valid_data}')
    lines += [f'  br i1 {valid}, label %body, label %invalid', 'invalid:',
              f'  store i32 2, ptr {status}, align 1', '  ret void', 'body:']

    def gpr(register):
        pointer = emit(f'getelementptr i8, ptr %state, i64 {register * 8}')
        return pointer, emit(f'load i64, ptr {pointer}, align 1')

    for insn in instructions:
        if insn.op == 'gpr':
            helper = f'{name}_scalar_{insn.pc}'
            helpers.append(lift_gpr(insn.raw + b'\xc3', helper))
            lines.append(f'  call void @{helper}(ptr %state)')
            continue
        address = str(insn.displacement)
        if insn.rip_relative:
            rip_ptr = emit(f'getelementptr i8, ptr %state, i64 {OFFSETS["rip"]}')
            rip = emit(f'load i64, ptr {rip_ptr}, align 1')
            address = emit(f'add i64 {rip}, {insn.pc + len(insn.raw) + insn.displacement}')
        if insn.base is not None:
            _, value = gpr(insn.base)
            address = emit(f'add i64 {value}, {insn.displacement}')
        if insn.index is not None:
            _, value = gpr(insn.index)
            scaled = emit(f'mul i64 {value}, {insn.scale}')
            address = emit(f'add i64 {address}, {scaled}')
        offset = emit(f'sub i64 {address}, {base}')
        at_or_above = emit(f'icmp uge i64 {address}, {base}')
        fits_size = emit(f'icmp uge i64 {size}, {insn.width // 8}')
        last = emit(f'sub i64 {size}, {insn.width // 8}')
        fits_offset = emit(f'icmp ule i64 {offset}, {last}')
        bounded = emit(f'and i1 {at_or_above}, {fits_size}')
        bounded = emit(f'and i1 {bounded}, {fits_offset}')
        pc = insn.pc
        lines += [f'  br i1 {bounded}, label %permission{pc}, label %bounds{pc}', f'bounds{pc}:',
                  f'  store i32 1, ptr {status}, align 1', f'  br label %fault{pc}', f'permission{pc}:']
        allowed = emit(f'and i64 {permissions}, {2 if insn.op == "store" else 1}')
        can_access = emit(f'icmp ne i64 {allowed}, 0')
        lines += [f'  br i1 {can_access}, label %access{pc}, label %denied{pc}', f'denied{pc}:',
                  f'  store i32 3, ptr {status}, align 1', f'  br label %fault{pc}', f'fault{pc}:',
                  f'  store i64 {address}, ptr {fields[4]}, align 8',
                  f'  store i64 {pc}, ptr {fields[5]}, align 8', '  ret void', f'access{pc}:']
        host = emit(f'getelementptr i8, ptr {data}, i64 {offset}')
        regptr, old = gpr(insn.reg)
        width = insn.width
        if insn.op == 'store':
            value = old if width == 64 else emit(f'trunc i64 {old} to i{width}')
            lines.append(f'  store i{width} {value}, ptr {host}, align 1')
        else:
            value = emit(f'load i{width}, ptr {host}, align 1')
            dest = insn.destination_width
            if insn.op in ('signed_load', 'zero_load'):
                value = emit(f'{"sext" if insn.op == "signed_load" else "zext"} i{width} {value} to i{dest}')
                width = dest
            if width < 64:
                value = emit(f'zext i{width} {value} to i64')
                if dest < 32:
                    retained = emit(f'and i64 {old}, {-1 ^ ((1 << dest) - 1)}')
                    value = emit(f'or i64 {retained}, {value}')
            lines.append(f'  store i64 {value}, ptr {regptr}, align 1')
    lines += [f'  store i32 0, ptr {status}, align 1', '  ret void', '}']
    return '\n\n'.join(helpers + ['\n'.join(lines)])
