"""Bounded register-only SSE/SSE2 experiment; not a general x86 decoder.

Two initialized XMM registers, masked MXCSR, final RET. Integer vectors lower to
LLVM integer operations. FP lanes call the pinned 8086-SSE SoftFloat adapter.
Unsupported instructions and FP controls fail closed, before guest mutation.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Instruction:
    op: str
    dst: int
    src: int
    width: int = 0
    scalar: bool = False
    immediate: int = 0


INTEGER = {
    0xfc: ('add', 8), 0xfd: ('add', 16), 0xfe: ('add', 32), 0xd4: ('add', 64),
    0xf8: ('sub', 8), 0xf9: ('sub', 16), 0xfa: ('sub', 32), 0xfb: ('sub', 64),
    0xdb: ('and', 128), 0xdf: ('andnot', 128), 0xeb: ('or', 128), 0xef: ('xor', 128),
    0x74: ('eq', 8), 0x75: ('eq', 16), 0x76: ('eq', 32),
    0x64: ('gt', 8), 0x65: ('gt', 16), 0x66: ('gt', 32),
}
FP = {0x58: 'fadd', 0x5c: 'fsub', 0x59: 'fmul', 0x5e: 'fdiv', 0x51: 'fsqrt'}
FP_IDS = {'fadd': 0, 'fsub': 1, 'fmul': 2, 'fdiv': 3, 'fsqrt': 4}


def decode(code):
    result = []
    offset = 0
    while offset < len(code):
        start = offset
        if code[offset] == 0xc3:
            if offset != len(code) - 1 or not result:
                raise ValueError('RET must terminate a nonempty fixture')
            return result
        prefix = None
        if code[offset] in (0x66, 0xf2, 0xf3):
            prefix = code[offset]
            offset += 1
        if code[offset:offset + 1] != b'\x0f' or offset + 2 >= len(code):
            raise ValueError(f'unsupported/truncated SSE instruction at {start:#x}')
        opcode, modrm = code[offset + 1:offset + 3]
        offset += 3
        dst, src = (modrm >> 3) & 7, modrm & 7
        if modrm >> 6 != 3 or src > 1:
            raise ValueError('only register operands XMM0/XMM1 are supported')
        if prefix == 0x66 and opcode in (0x71, 0x72, 0x73):
            width = {0x71: 16, 0x72: 32, 0x73: 64}[opcode]
            if dst not in (2, 4, 6) or (dst == 4 and width == 64) or offset >= len(code):
                raise ValueError('unsupported/truncated packed shift')
            result.append(Instruction({2: 'lshr', 4: 'ashr', 6: 'shl'}[dst],
                                      src, src, width, immediate=code[offset]))
            offset += 1
            continue
        if dst > 1:
            raise ValueError('only XMM0/XMM1 are supported')
        if opcode == 0x6f and prefix in (0x66, 0xf3):
            insn = Instruction('mov', dst, src)
        elif prefix == 0x66 and opcode in INTEGER:
            op, width = INTEGER[opcode]
            insn = Instruction(op, dst, src, width)
        elif prefix == 0x66 and opcode == 0x70:
            if offset >= len(code):
                raise ValueError('truncated PSHUFD')
            insn = Instruction('shuffle', dst, src, 32, immediate=code[offset])
            offset += 1
        elif opcode in FP:
            insn = Instruction(FP[opcode], dst, src,
                               64 if prefix in (0x66, 0xf2) else 32,
                               scalar=prefix in (0xf2, 0xf3))
        else:
            raise ValueError(f'unsupported encoding at {start:#x}')
        result.append(insn)
    raise ValueError('missing final RET')


def declarations():
    return ('declare i32 @bb_fp32(i32, i32, i32, ptr)\n'
            'declare i64 @bb_fp64(i64, i64, i32, ptr)\n')


def lift(code, name):
    if not name.isidentifier() or not name.isascii():
        raise ValueError('invalid function name')
    instructions = decode(code)
    lines = [f'define void @{name}(ptr %state) {{', 'entry:',
             '  %mxptr = getelementptr i8, ptr %state, i64 32',
             '  %statusptr = getelementptr i8, ptr %state, i64 36',
             '  %mx = load i32, ptr %mxptr, align 1',
             '  %reserved = and i32 %mx, -65536',  # MXCSR bits 16..31 are reserved
             '  %masks = and i32 %mx, 8064',
             '  %noreserved = icmp eq i32 %reserved, 0',
             '  %allmasked = icmp eq i32 %masks, 8064',
             '  %valid = and i1 %noreserved, %allmasked',
             '  br i1 %valid, label %body, label %reject',
             'reject:', '  store i32 1, ptr %statusptr, align 1', '  ret void',
             'body:', '  %p1 = getelementptr i8, ptr %state, i64 16',
             '  %x0 = load i128, ptr %state, align 1',
             '  %x1 = load i128, ptr %p1, align 1']
    registers = ['%x0', '%x1']
    serial = 0

    def emit(expression):
        nonlocal serial
        serial += 1
        value = f'%s{serial}'
        lines.append(f'  {value} = {expression}')
        return value

    for insn in instructions:
        a, b = registers[insn.dst], registers[insn.src]
        if insn.op == 'mov':
            value = b
        elif insn.op in FP_IDS:
            width = insn.width
            ty = f'<{128 // width} x i{width}>'
            av = emit(f'bitcast i128 {a} to {ty}')
            bv = emit(f'bitcast i128 {b} to {ty}')
            value = av  # legacy scalar SSE preserves the other destination lanes
            for lane in range(1 if insn.scalar else 128 // width):
                aa = emit(f'extractelement {ty} {av}, i32 {lane}')
                bb = emit(f'extractelement {ty} {bv}, i32 {lane}')
                out = emit(f'call i{width} @bb_fp{width}(i{width} {aa}, i{width} {bb}, '
                           f'i32 {FP_IDS[insn.op]}, ptr %mxptr)')
                value = emit(f'insertelement {ty} {value}, i{width} {out}, i32 {lane}')
            value = emit(f'bitcast {ty} {value} to i128')
        elif insn.width == 128:
            if insn.op == 'andnot':
                a = emit(f'xor i128 {a}, -1')
            value = emit(f'{"and" if insn.op == "andnot" else insn.op} i128 {a}, {b}')
        else:
            width, count = insn.width, 128 // insn.width
            ty = f'<{count} x i{width}>'
            av = emit(f'bitcast i128 {a} to {ty}')
            bv = emit(f'bitcast i128 {b} to {ty}')
            if insn.op in ('eq', 'gt'):
                mask = emit(f'icmp {"eq" if insn.op == "eq" else "sgt"} {ty} {av}, {bv}')
                value = emit(f'sext <{count} x i1> {mask} to {ty}')
            elif insn.op == 'shuffle':
                indices = ', '.join(f'i32 {(insn.immediate >> (i * 2)) & 3}' for i in range(4))
                value = emit(f'shufflevector {ty} {bv}, {ty} zeroinitializer, <4 x i32> <{indices}>')
            elif insn.op in ('shl', 'lshr', 'ashr'):
                shift = min(insn.immediate, width - 1)
                if insn.immediate >= width and insn.op != 'ashr':
                    value = 'zeroinitializer'
                else:
                    shifts = ', '.join(f'i{width} {shift}' for _ in range(count))
                    value = emit(f'{insn.op} {ty} {av}, <{shifts}>')
            else:
                value = emit(f'{insn.op} {ty} {av}, {bv}')
            value = emit(f'bitcast {ty} {value} to i128')
        registers[insn.dst] = value
    lines += [f'  store i128 {registers[0]}, ptr %state, align 1',
              f'  store i128 {registers[1]}, ptr %p1, align 1',
              '  store i32 0, ptr %statusptr, align 1', '  ret void', '}']
    return '\n'.join(lines)
