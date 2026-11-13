"""Little-endian experiment CPU-state ABI v1, shared by SIMD IR and its oracle.

Storage for GPRs/RIP/RFLAGS is a foundation; the SIMD contract preserves these
fields. It does not implement GPR execution, arithmetic flags or guest dispatch.
"""
import struct

ABI_VERSION = 1
GPR_NAMES = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
STATE = struct.Struct('<16Q32Q2QIIQ')
XMM_OFFSET = 128
XMM_INDEX = 16
RIP_INDEX, RFLAGS_INDEX, MXCSR_INDEX, STATUS_INDEX = 48, 49, 50, 51
MXCSR_OFFSET, STATUS_OFFSET = 400, 404
OFFSETS = {'gpr': 0, 'xmm': XMM_OFFSET, 'rip': 384, 'rflags': 392,
           'mxcsr': MXCSR_OFFSET, 'status': STATUS_OFFSET, 'reserved': 408}


def xmm_offset(register):
    if not isinstance(register, int) or not 0 <= register < 16:
        raise ValueError('XMM index must be 0..15')
    return XMM_OFFSET + register * 16


def c_layout_checks():
    """Have each C build check its actual layout against Python/LLVM offsets."""
    return '#include <stddef.h>\n#include "cpu_state.h"\n' + '\n'.join([
        f'_Static_assert(sizeof(BbCpuState) == {STATE.size}, "CPU-state size");',
        '_Static_assert(_Alignof(BbCpuState) == 8, "CPU-state alignment");',
        *[f'_Static_assert(offsetof(BbCpuState, {name}) == {offset}, "{name} offset");'
          for name, offset in OFFSETS.items()]]) + '\n'


def expand_legacy(record, index):
    """Embed the historical two-XMM corpus, retaining distinct other registers."""
    x0, x1, y0, y1, mxcsr, status, reserved = struct.unpack('<4QIIQ', record)
    mask = (1 << 64) - 1
    gpr = [((0x0123456789abcdef * (r + 1)) ^ (index * 0x100000001)) & mask for r in range(16)]
    xmm = [x0, x1, y0, y1]
    for r in range(2, 16):
        # Rotate edge patterns between both operands, perturbing upper lanes so
        # aliases, missing REX bits and accidental scalar zeroing are visible.
        lo = (x0, y0, x1, y1)[r % 4]
        hi = (x1, y1, x0, y0)[r % 4] ^ (0x0101010101010101 * r)
        xmm.extend((lo, hi & mask))
    flags = 0x202 | ((index * 0x89) & 0x8d5)
    return STATE.pack(*gpr, *xmm, 0x200000000 + index * 16, flags, mxcsr, status, reserved)
