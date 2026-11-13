"""Bounded register-only SSE/SSE2 experiment; not a general x86 decoder.

Sixteen initialized XMM registers, masked MXCSR, final RET. Integer vectors lower to
LLVM integer operations. FP lanes call the pinned 8086-SSE SoftFloat adapter.
Unsupported instructions and FP controls fail closed, before guest mutation.
"""
from dataclasses import dataclass
from cpu_state import MXCSR_OFFSET, STATUS_OFFSET, xmm_offset


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
    0xec: ('sadd_sat', 8), 0xed: ('sadd_sat', 16),
    0xdc: ('uadd_sat', 8), 0xdd: ('uadd_sat', 16),
    0xe8: ('ssub_sat', 8), 0xe9: ('ssub_sat', 16),
    0xd8: ('usub_sat', 8), 0xd9: ('usub_sat', 16),
    0x60: ('unpacklo', 8), 0x61: ('unpacklo', 16),
    0x62: ('unpacklo', 32), 0x6c: ('unpacklo', 64),
    0x68: ('unpackhi', 8), 0x69: ('unpackhi', 16),
    0x6a: ('unpackhi', 32), 0x6d: ('unpackhi', 64),
    0x63: ('pack_signed', 16), 0x6b: ('pack_signed', 32),
    0x67: ('pack_unsigned', 16),
    0xd5: ('mullo', 16), 0xe5: ('mulhi_signed', 16),
    0xe4: ('mulhi_unsigned', 16), 0xf5: ('madd', 16),
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
        rex = 0
        if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
            rex = code[offset]
            # W and X are outside this canonical register-only contract.
            if rex & 0x0a:
                raise ValueError('unsupported REX.W/REX.X bits')
            offset += 1
        if code[offset:offset + 1] != b'\x0f' or offset + 2 >= len(code):
            raise ValueError(f'unsupported/truncated SSE instruction at {start:#x}')
        opcode, modrm = code[offset + 1:offset + 3]
        offset += 3
        group = (modrm >> 3) & 7
        dst, src = group + ((rex & 4) << 1), (modrm & 7) + ((rex & 1) << 3)
        if modrm >> 6 != 3:
            raise ValueError('only register operands XMM0..XMM15 are supported')
        if prefix == 0x66 and opcode in (0x71, 0x72, 0x73):
            width = {0x71: 16, 0x72: 32, 0x73: 64}[opcode]
            if rex & 4 or group not in (2, 4, 6) or (group == 4 and width == 64) or offset >= len(code):
                raise ValueError('unsupported/truncated packed shift')
            result.append(Instruction({2: 'lshr', 4: 'ashr', 6: 'shl'}[group],
                                      src, src, width, immediate=code[offset]))
            offset += 1
            continue
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
            'declare i64 @bb_fp64(i64, i64, i32, ptr)\n'
            'declare i64 @bb_simd_host_save()\n'
            'declare void @bb_simd_host_restore(i64)\n' + ''.join(
                f'declare <{128 // w} x i{w}> @llvm.{op}.sat.v{128 // w}i{w}'
                f'(<{128 // w} x i{w}>, <{128 // w} x i{w}>)\n'
                for op in ('sadd', 'uadd', 'ssub', 'usub') for w in (8, 16)))


def lift(code, name):
    if not name.isidentifier() or not name.isascii():
        raise ValueError('invalid function name')
    instructions = decode(code)
    lines = [f'define void @{name}(ptr %state) {{', 'entry:',
             f'  %mxptr = getelementptr i8, ptr %state, i64 {MXCSR_OFFSET}',
             f'  %statusptr = getelementptr i8, ptr %state, i64 {STATUS_OFFSET}',
             '  %mx = load i32, ptr %mxptr, align 1',
             '  %reserved = and i32 %mx, -65536',  # MXCSR bits 16..31 are reserved
             '  %masks = and i32 %mx, 8064',
             '  %noreserved = icmp eq i32 %reserved, 0',
             '  %allmasked = icmp eq i32 %masks, 8064',
             '  %valid = and i1 %noreserved, %allmasked',
             '  br i1 %valid, label %body, label %reject',
             'reject:', '  store i32 1, ptr %statusptr, align 1', '  ret void',
             'body:', '  %host = call i64 @bb_simd_host_save()']
    for register in range(16):
        lines += [f'  %p{register} = getelementptr i8, ptr %state, i64 {xmm_offset(register)}',
                  f'  %x{register} = load i128, ptr %p{register}, align 1']
    registers = [f'%x{r}' for r in range(16)]
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
            if insn.op.endswith('_sat'):
                op = insn.op.removesuffix('_sat')
                value = emit(f'call {ty} @llvm.{op}.sat.v{count}i{width}({ty} {av}, {ty} {bv})')
            elif insn.op in ('unpacklo', 'unpackhi'):
                start = 0 if insn.op == 'unpacklo' else count // 2
                indices = ', '.join(f'i32 {i + base}' for i in range(start, start + count // 2)
                                    for base in (0, count))
                value = emit(f'shufflevector {ty} {av}, {ty} {bv}, <{count} x i32> <{indices}>')
            elif insn.op in ('pack_signed', 'pack_unsigned'):
                # Both PACKSS and PACKUS interpret their *input* lanes as signed.
                narrow = width // 2
                lower = -(1 << (narrow - 1)) if insn.op == 'pack_signed' else 0
                upper = (1 << (narrow - (insn.op == 'pack_signed'))) - 1
                limits = lambda n: '<' + ', '.join(f'i{width} {n}' for _ in range(count)) + '>'
                packed = []
                for operand in (av, bv):
                    below = emit(f'icmp slt {ty} {operand}, {limits(lower)}')
                    clamped = emit(f'select <{count} x i1> {below}, {ty} {limits(lower)}, {ty} {operand}')
                    above = emit(f'icmp sgt {ty} {clamped}, {limits(upper)}')
                    clamped = emit(f'select <{count} x i1> {above}, {ty} {limits(upper)}, {ty} {clamped}')
                    packed.append(emit(f'trunc {ty} {clamped} to <{count} x i{narrow}>'))
                indices = ', '.join(f'i32 {i}' for i in range(count * 2))
                value = emit(f'shufflevector <{count} x i{narrow}> {packed[0]}, '
                             f'<{count} x i{narrow}> {packed[1]}, <{count * 2} x i32> <{indices}>')
                ty = f'<{count * 2} x i{narrow}>'
            elif insn.op == 'mullo':
                value = emit(f'mul {ty} {av}, {bv}')
            elif insn.op in ('mulhi_signed', 'mulhi_unsigned', 'madd'):
                wide = f'<{count} x i32>'
                ext = 'zext' if insn.op == 'mulhi_unsigned' else 'sext'
                aa = emit(f'{ext} {ty} {av} to {wide}')
                bb = emit(f'{ext} {ty} {bv} to {wide}')
                product = emit(f'mul {wide} {aa}, {bb}')
                if insn.op == 'madd':
                    halves = []
                    for parity in (0, 1):
                        indices = ', '.join(f'i32 {i}' for i in range(parity, count, 2))
                        halves.append(emit(f'shufflevector {wide} {product}, {wide} zeroinitializer, '
                                           f'<4 x i32> <{indices}>'))
                    ty = '<4 x i32>'
                    # No nsw/nuw: (-32768)^2 + (-32768)^2 wraps to 0x80000000.
                    value = emit(f'add {ty} {halves[0]}, {halves[1]}')
                else:
                    shifts = '<' + ', '.join('i32 16' for _ in range(count)) + '>'
                    high = emit(f'lshr {wide} {product}, {shifts}')
                    value = emit(f'trunc {wide} {high} to {ty}')
            elif insn.op in ('eq', 'gt'):
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
    lines += [f'  store i128 {value}, ptr %p{r}, align 1' for r, value in enumerate(registers)]
    lines += ['  store i32 0, ptr %statusptr, align 1',
              '  call void @bb_simd_host_restore(i64 %host)', '  ret void', '}']
    return '\n'.join(lines)
