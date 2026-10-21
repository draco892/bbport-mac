"""Strict P0 leaf experiment, not a general x86 decoder or a game lifter.

Input: RDI/RSI, output: RAX. No observable flags, memory, stack or calls.
Only the exact encodings below are accepted; everything else fails closed.
"""


def lift(code, name):
    if not name.isidentifier() or not name.isascii():
        raise ValueError("invalid function name")
    lines = [f"define i64 @{name}(i64 %a, i64 %b) {{"]
    value = None
    serial = 0

    def emit(expression):
        nonlocal serial
        serial += 1
        result = f"%v{serial}"
        lines.append(f"  {result} = {expression}")
        return result

    offset = 0
    while offset < len(code):
        start = offset
        wide = code[offset] == 0x48
        if wide:
            offset += 1
        width = 64 if wide else 32
        pair = code[offset:offset + 2]
        offset += 2
        if pair == b"\x89\xf8":  # mov rax,rdi / mov eax,edi
            value = "%a" if wide else emit("trunc i64 %a to i32")
            if not wide:
                value = emit(f"zext i32 {value} to i64")
        elif pair in (b"\x01\xf0", b"\x29\xf0", b"\x31\xf0",
                      b"\x21\xf0", b"\x09\xf0") or pair in (
                          b"\xc1\xe0", b"\xc1\xe8", b"\xc1\xf8"):
            if value is None:
                raise ValueError(f"undefined RAX at {start:#x}")
            left = value if wide else emit(f"trunc i64 {value} to i32")
            if pair[0] == 0xc1:
                if offset >= len(code):
                    raise ValueError("truncated shift")
                right = str(code[offset] & (width - 1))
                offset += 1
                operation = {0xe0: "shl", 0xe8: "lshr", 0xf8: "ashr"}[pair[1]]
            else:
                right = "%b" if wide else emit("trunc i64 %b to i32")
                operation = {1: "add", 0x29: "sub", 0x31: "xor",
                             0x21: "and", 9: "or"}[pair[0]]
            value = emit(f"{operation} i{width} {left}, {right}")
            if not wide:
                value = emit(f"zext i32 {value} to i64")
        elif not wide and code[start:] == b"\xc3" and value is not None:
            lines.extend([f"  ret i64 {value}", "}"])
            return "\n".join(lines)
        else:
            raise ValueError(f"unsupported encoding at {start:#x}: {code[start:].hex()}")
    raise ValueError("missing final RET")
