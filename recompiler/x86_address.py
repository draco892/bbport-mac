"""ModR/M and SIB addressing for the bounded x86-64 decoders."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Address:
    base: int | None
    index: int | None
    scale: int
    displacement: int
    rip_relative: bool = False


def decode_address(code, offset, modrm, rex, *, allow_rip=False):
    """Decode 64-bit addressing after ModR/M."""
    mode, rm = modrm >> 6, modrm & 7
    if mode == 3:
        raise ValueError('expected memory addressing')
    base, index, scale = None, None, 1
    rip_relative = False
    disp_size = (0, 1, 4)[mode]
    if rm == 4:
        if offset >= len(code):
            raise ValueError('missing SIB')
        sib = code[offset]
        offset += 1
        raw_index, raw_base = (sib >> 3) & 7, sib & 7
        scale = 1 << (sib >> 6)
        if raw_index != 4 or rex & 2:
            index = raw_index | ((rex & 2) << 2)
        if mode == 0 and raw_base == 5:
            if rex & 1:
                raise ValueError('noncanonical REX.B on no-base SIB')
            disp_size = 4
        else:
            base = raw_base | ((rex & 1) << 3)
    elif mode == 0 and rm == 5:
        if not allow_rip or rex & 1:
            raise ValueError('unsupported RIP-relative addressing')
        rip_relative = True
        disp_size = 4
    else:
        if rex & 2:
            raise ValueError('REX.X without SIB')
        base = rm | ((rex & 1) << 3)
    end = offset + disp_size
    if end > len(code):
        raise ValueError('truncated displacement')
    displacement = int.from_bytes(code[offset:end], 'little', signed=True)
    return Address(base, index, scale, displacement, rip_relative), end
