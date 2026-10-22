"""Bounded indirect calls through an explicit guest-address/native-code registry."""
from stack_lift import StackInstruction, assemble, decode_extra, lift_stack

# Above the x86 Mach-O PAGEZERO region; also exercises full 64-bit code pointers.
CODE_BASE = 0x200000000


def decode_indirect(code, pc):
    if code.startswith(b'\xff\xd0', pc):
        return StackInstruction(pc, 2, 'indirect_call', source='rax')
    if code.startswith(b'\xff\xd3', pc):
        return StackInstruction(pc, 2, 'indirect_call', source='rbx')
    if code.startswith(b'\xff\x17', pc):
        return StackInstruction(pc, 2, 'indirect_call', base='guest')
    if code.startswith(b'\xff\x57', pc):
        if pc + 3 > len(code):
            raise ValueError('truncated indirect memory displacement')
        displacement = int.from_bytes(code[pc + 2:pc + 3], 'little', signed=True)
        if not 0 <= displacement <= 56:
            raise ValueError('indirect memory operand outside 64-byte region')
        return StackInstruction(pc, 3, 'indirect_call', base='guest', displacement=displacement)
    return decode_extra(code, pc)


def assemble_indirect(specification):
    converted, targets = {}, {}
    for name, function in specification.items():
        parts, pc = [], 0
        for part in function['parts']:
            if isinstance(part, dict) and 'indirect' in part:
                if set(part) != {'indirect', 'targets'} or not isinstance(part['targets'], list):
                    raise ValueError('invalid indirect fixture token')
                operand = part['indirect']
                if operand in ('rax', 'rbx'):
                    code = b'\xff\xd0' if operand == 'rax' else b'\xff\xd3'
                elif type(operand) is int and 0 <= operand <= 56:
                    code = b'\xff\x17' if operand == 0 else b'\xff\x57' + bytes([operand])
                else:
                    raise ValueError('unsupported indirect fixture operand')
                targets[(name, pc)] = tuple(part['targets'])
                parts.append(code.hex())
                pc += len(code)
            else:
                parts.append(part)
                pc += len(bytes.fromhex(part)) if isinstance(part, str) else 5
        converted[name] = {'address': function['address'], 'parts': parts}
    return assemble(converted), targets


def lift_indirect(specification):
    functions, targets = assemble_indirect(specification)
    ir, analyses = lift_stack(functions, indirect_targets=targets,
                              decoder_extra=decode_indirect, code_base=CODE_BASE)
    return ir, analyses, functions, targets
