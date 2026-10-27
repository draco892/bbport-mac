"""Synthetic host-import calls sharing the indirect registry and explicit CPU state."""
from indirect_lift import CODE_BASE, assemble_indirect, decode_indirect
from stack_lift import lift_stack

HOST_IMPORTS = {'host_service': 0x4000}


def lift_callbacks(specification):
    converted = {}
    for name, function in specification.items():
        if name in HOST_IMPORTS:
            raise ValueError('guest function conflicts with a host import')
        parts = []
        for part in function['parts']:
            if isinstance(part, dict) and 'call_host' in part:
                if set(part) != {'call_host'} or part['call_host'] not in HOST_IMPORTS:
                    raise ValueError('unknown host import token')
                part = {'call': part['call_host']}
            parts.append(part)
        converted[name] = {'address': function['address'], 'parts': parts}
    # These placeholders let the fixture assembler calculate rel32 displacements.
    # They are removed before analysis and never become guest registry entries.
    converted.update({name: {'address': address, 'parts': ['c3']}
                      for name, address in HOST_IMPORTS.items()})
    functions, targets = assemble_indirect(converted)
    for name in HOST_IMPORTS:
        del functions[name]
    ir, analyses = lift_stack(functions, indirect_targets=targets, decoder_extra=decode_indirect,
                              code_base=CODE_BASE, host_imports=HOST_IMPORTS)
    return ir, analyses, functions, targets
