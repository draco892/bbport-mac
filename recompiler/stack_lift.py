"""Synthetic bounded stack and statically resolved direct calls; not a game backend."""
from dataclasses import dataclass

from memory_lift import Instruction, decode

STACK_BYTES = 512
FRAME_BYTES = 128
ROOT_RETURN = 0xfffffffffffffff0
FIELDS = {'rax': 0, 'b': 1, 'rbx': 2, 'rbp': 3, 'sp': 4}


def assemble(specification):
    """Resolve explicit CALL tokens in synthetic fixtures, not arbitrary assembly."""
    if not isinstance(specification, dict) or not specification:
        raise ValueError('expected a non-empty function map')
    functions = {}
    for name, function in specification.items():
        code = bytearray()
        for part in function['parts']:
            if isinstance(part, str):
                code.extend(bytes.fromhex(part))
            elif isinstance(part, dict) and set(part) == {'call'} and part['call'] in specification:
                target = specification[part['call']]['address']
                relative = target - (function['address'] + len(code) + 5)
                code.extend(b'\xe8' + relative.to_bytes(4, 'little', signed=True))
            else:
                raise ValueError('unsupported fixture part or unknown call token')
        functions[name] = {'address': function['address'], 'code': bytes(code)}
    return functions


@dataclass(frozen=True)
class StackInstruction(Instruction):
    destination: str = ''
    base: str = ''


def decode_extra(code, pc):
    byte = code[pc]
    if byte in (0x50, 0x53, 0x55, 0x56, 0x58, 0x5b, 0x5d, 0x5e):
        reg = {0: 'rax', 3: 'rbx', 5: 'rbp', 6: 'b'}[byte & 7]
        return StackInstruction(pc, 1, 'pop' if byte & 8 else 'push', source=reg)
    if byte == 0xc9:
        return StackInstruction(pc, 1, 'leave')
    if byte == 0xe8:
        if pc + 5 > len(code):
            raise ValueError('truncated direct call')
        relative = int.from_bytes(code[pc + 1:pc + 5], 'little', signed=True)
        return StackInstruction(pc, 5, 'call', target=pc + 5 + relative)
    moves = {b'\x48\x89\xe5': ('frame', '', ''),
             b'\x48\x89\xd8': ('move_reg', 'rbx', 'rax'),
             b'\x48\x89\xc3': ('move_reg', 'rax', 'rbx'),
             b'\x48\x89\xc6': ('move_reg', 'rax', 'b'),
             b'\x48\x89\xf3': ('move_reg', 'b', 'rbx'),
             b'\x48\x89\xde': ('move_reg', 'rbx', 'b')}
    for encoding, (op, source, destination) in moves.items():
        if code.startswith(encoding, pc):
            return StackInstruction(pc, len(encoding), op, source=source, destination=destination)
    for encoding, op in ((b'\x48\x83\xec', 'reserve'), (b'\x48\x83\xc4', 'release')):
        if code.startswith(encoding, pc):
            if pc + 4 > len(code):
                raise ValueError('truncated stack adjustment')
            amount = code[pc + 3]
            if not 0 < amount < 128 or amount % 8:
                raise ValueError('stack adjustment must be a positive aligned imm8')
            return StackInstruction(pc, 4, op, displacement=amount)
    for encoding, op in ((b'\x48\x89', 'stack_store'), (b'\x48\x8b', 'stack_load')):
        if not code.startswith(encoding, pc) or pc + 2 >= len(code):
            continue
        modrm = code[pc + 2]
        if modrm not in (4, 0x34, 0x44, 0x74, 0x45, 0x75):
            continue
        reg = 'b' if modrm & 0x30 else 'rax'
        base = 'rbp' if modrm in (0x45, 0x75) else 'sp'
        size = 3
        displacement = 0
        if base == 'sp':
            if pc + size >= len(code) or code[pc + size] != 0x24:
                raise ValueError('unsupported stack SIB')
            size += 1
        if modrm & 0x40:
            if pc + size >= len(code):
                raise ValueError('truncated stack displacement')
            displacement = int.from_bytes(code[pc + size:pc + size + 1], 'little', signed=True)
            size += 1
        return StackInstruction(pc, size, op, source=reg, base=base, displacement=displacement)
    return None


def analyze(functions, *, indirect_targets=None, decoder_extra=None):
    if not functions:
        raise ValueError('empty function map')
    addresses, decoded = {}, {}
    for name, function in functions.items():
        if not name.isidentifier() or not name.isascii():
            raise ValueError('invalid function name')
        address = function['address']
        if not isinstance(address, int) or not 0 <= address < (1 << 31):
            raise ValueError('invalid synthetic code address')
        if address in addresses:
            raise ValueError('duplicate function address')
        addresses[address] = name
        decoded[name] = decode(function['code'], decoder_extra or decode_extra)
    spans = sorted((f['address'], f['address'] + len(f['code'])) for f in functions.values())
    if any(right[0] < left[1] for left, right in zip(spans, spans[1:])):
        raise ValueError('overlapping functions')
    analyses = {}
    used_indirect_sites = set()
    for name, instructions in decoded.items():
        regs = {'rax': None, 'b': 'value', 'rbx': 'entry_rbx', 'rbp': 'entry_rbp'}
        sp, minimum = 0, 0
        slots, locations, calls, indirect_calls = {}, {}, {}, {}

        def read(reg):
            value = regs[reg]
            if value is None:
                raise ValueError(f'{name}: undefined {reg}')
            return value

        def scalar(value, destination):
            if destination != 'rbp' and (value == 'entry_rbp' or isinstance(value, tuple)):
                raise ValueError(f'{name}: frame pointer escapes the stack contract')
            return value

        def trim():
            for offset in list(slots):
                if offset < sp:
                    del slots[offset]

        for index, ins in enumerate(instructions):
            if ins.op == 'ret' and index != len(instructions) - 1:
                raise ValueError(f'{name}: unreachable code after RET')
            if ins.op in ('load', 'signed_load', 'mov'):
                regs['rax'] = 'value'
            elif ins.op == 'store':
                scalar(read(ins.source), 'memory')
            elif ins.op in ('add', 'sub', 'xor'):
                scalar(read('rax'), 'rax')
                regs['rax'] = 'value'
            elif ins.op == 'move_reg':
                regs[ins.destination] = scalar(read(ins.source), ins.destination)
            elif ins.op == 'push':
                value = read(ins.source)
                sp -= 8
                slots[sp] = value
                locations[ins.pc] = sp
            elif ins.op == 'pop':
                if sp >= 0 or sp not in slots:
                    raise ValueError(f'{name}: pop reads uninitialized/protected stack data')
                locations[ins.pc] = sp
                regs[ins.source] = scalar(slots[sp], ins.source)
                sp += 8
                trim()
            elif ins.op == 'reserve':
                sp -= ins.displacement
            elif ins.op == 'release':
                sp += ins.displacement
                if sp > 0:
                    raise ValueError(f'{name}: stack release crosses the return address')
                trim()
            elif ins.op == 'frame':
                regs['rbp'] = ('frame', sp)
            elif ins.op in ('stack_load', 'stack_store'):
                base = sp
                if ins.base == 'rbp':
                    if not isinstance(regs['rbp'], tuple):
                        raise ValueError(f'{name}: RBP is not a local frame pointer')
                    base = regs['rbp'][1]
                offset = base + ins.displacement
                if offset % 8 or offset < sp or offset + 8 > 0:
                    raise ValueError(f'{name}: stack operand outside allocated frame')
                locations[ins.pc] = offset
                if ins.op == 'stack_store':
                    slots[offset] = read(ins.source)
                else:
                    if offset not in slots:
                        raise ValueError(f'{name}: uninitialized stack read')
                    regs[ins.source] = scalar(slots[offset], ins.source)
            elif ins.op == 'leave':
                frame = regs['rbp']
                if not isinstance(frame, tuple) or not sp <= frame[1] < 0 or frame[1] not in slots:
                    raise ValueError(f'{name}: invalid LEAVE frame')
                locations[ins.pc] = frame[1]
                regs['rbp'] = slots[frame[1]]
                sp = frame[1] + 8
                trim()
            elif ins.op == 'call':
                target = functions[name]['address'] + ins.target
                if target not in addresses:
                    raise ValueError(f'{name}: call target is not a known function entry')
                if sp % 16 != 8:
                    raise ValueError(f'{name}: stack is not 16-byte aligned before CALL')
                calls[ins.pc] = (addresses[target], sp)
                regs['rax'] = regs['b'] = 'value'
            elif ins.op == 'indirect_call':
                if indirect_targets is None:
                    raise ValueError('indirect calls require an explicit target-set contract')
                site = (name, ins.pc)
                options = indirect_targets.get(site)
                if (not options or any(not isinstance(t, str) for t in options)
                        or len(options) != len(set(options)) or any(t not in functions for t in options)):
                    raise ValueError(f'{name}: missing or invalid indirect target set')
                if ins.base != 'guest':
                    scalar(read(ins.source), 'call target')
                if sp % 16 != 8:
                    raise ValueError(f'{name}: stack is not 16-byte aligned before CALL')
                used_indirect_sites.add(site)
                indirect_calls[ins.pc] = (tuple(options), sp)
                regs['rax'] = regs['b'] = 'value'
            elif ins.op == 'ret':
                scalar(read('rax'), 'rax')
                if sp != 0 or regs['rbx'] != 'entry_rbx' or regs['rbp'] != 'entry_rbp':
                    raise ValueError(f'{name}: RET must restore RSP, RBX and RBP')
            else:
                raise ValueError(f'{name}: unsupported stack/call operation {ins.op}')
            minimum = min(minimum, sp)
            if sp < -FRAME_BYTES:
                raise ValueError(f'{name}: local frame exceeds {FRAME_BYTES} bytes')
            # Save the post-instruction stack depth for explicit state emission.
            locations[('sp', ins.pc)] = sp
        if instructions[-1].op != 'ret':
            raise ValueError(f'{name}: missing RET')
        analyses[name] = {'instructions': instructions, 'locations': locations,
                          'calls': calls, 'indirect_calls': indirect_calls, 'required_stack': -minimum}
    if indirect_targets is not None and set(indirect_targets) != used_indirect_sites:
        raise ValueError('indirect target contract names a non-call site')
    visiting, completed = set(), set()

    def required(name):
        if name in visiting:
            raise ValueError('recursive/cyclic call graphs are unsupported')
        if name not in completed:
            visiting.add(name)
            edges = list(analyses[name]['calls'].values())
            edges.extend((callee, depth) for targets, depth in analyses[name]['indirect_calls'].values()
                         for callee in targets)
            for callee, depth in edges:
                analyses[name]['required_stack'] = max(analyses[name]['required_stack'],
                                                       -depth + 8 + required(callee))
            visiting.remove(name)
            completed.add(name)
        result = analyses[name]['required_stack']
        if result > STACK_BYTES - 8:
            raise ValueError('nested calls exceed the bounded guest stack')
        return result

    for name in functions:
        required(name)
    return analyses


def lift_stack(functions, *, indirect_targets=None, decoder_extra=None, code_base=0):
    analyses = analyze(functions, indirect_targets=indirect_targets, decoder_extra=decoder_extra)
    indirect_mode = indirect_targets is not None
    if not isinstance(code_base, int) or not 0 <= code_base <= (1 << 64) - 1 - max(
            f['address'] + len(f['code']) for f in functions.values()):
        raise ValueError('invalid guest code base')
    state_fields = {**FIELDS, 'error': 5, 'fault_address': 6} if indirect_mode else FIELDS
    module = ['%CPU = type { ' + ', '.join(['i64'] * len(state_fields)) + ' }', 'declare void @llvm.trap()']
    if indirect_mode:
        resolver = ['define ptr @resolve_guest_code(i64 %address) noinline {', 'entry:',
                    '  switch i64 %address, label %unknown [']
        resolver.extend(f'    i64 {code_base + f["address"]}, label %r{i}'
                        for i, f in enumerate(functions.values()))
        resolver.extend(['  ]', 'unknown:', '  ret ptr null'])
        for i, name in enumerate(functions):
            resolver.extend([f'r{i}:', f'  ret ptr @translated_{name}'])
        resolver.append('}')
        module.append('\n'.join(resolver))
    for name, analysis in analyses.items():
        lines = [f'define void @translated_{name}(ptr %cpu, ptr %guest, ptr %stack, i64 %expected) noinline {{',
                 'entry:']
        serial = 0

        def emit(expression):
            nonlocal serial
            serial += 1
            result = f'%v{serial}'
            lines.append(f'  {result} = {expression}')
            return result

        fields = {reg: emit(f'getelementptr %CPU, ptr %cpu, i32 0, i32 {index}')
                  for reg, index in state_fields.items()}

        def read(reg):
            return emit(f'load i64, ptr {fields[reg]}')

        def write(reg, value):
            lines.append(f'  store i64 {value}, ptr {fields[reg]}')

        def guard(condition):
            label = f'ok{serial}'
            lines.append(f'  br i1 {condition}, label %{label}, label %fault')
            lines.append(f'{label}:')

        entry_sp, entry_rbx, entry_rbp = read('sp'), read('rbx'), read('rbp')
        low = emit(f'icmp uge i64 {entry_sp}, {analysis["required_stack"]}')
        high = emit(f'icmp ule i64 {entry_sp}, {STACK_BYTES - 8}')
        aligned = emit(f'icmp eq i64 {emit(f"and i64 {entry_sp}, 15")}, 8')
        within = emit(f'and i1 {low}, {high}')
        guard(emit(f'and i1 {within}, {aligned}'))

        def stack_offset(offset):
            return emit(f'add i64 {entry_sp}, {offset}')

        def stack_address(offset):
            return emit(f'getelementptr i8, ptr %stack, i64 {stack_offset(offset)}')

        def narrow(value, width):
            return value if width == 64 else emit(f'trunc i64 {value} to i{width}')

        def extend(value, width, signed=False):
            return value if width == 64 else emit(f'{"sext" if signed else "zext"} i{width} {value} to i64')

        for ins in analysis['instructions']:
            locations = analysis['locations']
            sp = locations[('sp', ins.pc)]
            if ins.op in ('load', 'signed_load', 'store'):
                address = emit(f'getelementptr i8, ptr %guest, i64 {ins.displacement}')
                if ins.op == 'store':
                    value = narrow(read(ins.source), ins.width)
                    lines.append(f'  store i{ins.width} {value}, ptr {address}, align 1')
                else:
                    value = emit(f'load i{ins.width}, ptr {address}, align 1')
                    write('rax', extend(value, ins.width, ins.op == 'signed_load'))
            elif ins.op == 'mov':
                write('rax', extend(narrow(read('b'), ins.width), ins.width))
            elif ins.op in ('add', 'sub', 'xor'):
                left, right = narrow(read('rax'), ins.width), narrow(read('b'), ins.width)
                write('rax', extend(emit(f'{ins.op} i{ins.width} {left}, {right}'), ins.width))
            elif ins.op == 'move_reg':
                write(ins.destination, read(ins.source))
            elif ins.op in ('push', 'stack_store'):
                address = stack_address(locations[ins.pc])
                lines.append(f'  store i64 {read(ins.source)}, ptr {address}, align 1')
            elif ins.op in ('pop', 'stack_load', 'leave'):
                address = stack_address(locations[ins.pc])
                write('rbp' if ins.op == 'leave' else ins.source,
                      emit(f'load i64, ptr {address}, align 1'))
            elif ins.op == 'frame':
                write('rbp', emit(f'ptrtoint ptr {stack_address(sp)} to i64'))
            elif ins.op in ('call', 'indirect_call'):
                if ins.op == 'call':
                    callee, depth = analysis['calls'][ins.pc]
                    native = f'@translated_{callee}'
                else:
                    options, depth = analysis['indirect_calls'][ins.pc]
                    if ins.base == 'guest':
                        address = emit(f'getelementptr i8, ptr %guest, i64 {ins.displacement}')
                        target = emit(f'load i64, ptr {address}, align 1')
                    else:
                        target = read(ins.source)
                    native = emit(f'call ptr @resolve_guest_code(i64 {target})')
                    known = emit(f'icmp ne ptr {native}, null')
                    lines.extend([f'  br i1 {known}, label %known{ins.pc}, label %unknown{ins.pc}',
                                  f'unknown{ins.pc}:'])
                    write('error', '1')
                    write('fault_address', target)
                    lines.extend(['  br label %unwind', f'known{ins.pc}:'])
                    allowed = None
                    for callee in options:
                        match = emit(f'icmp eq i64 {target}, {code_base + functions[callee]["address"]}')
                        allowed = match if allowed is None else emit(f'or i1 {allowed}, {match}')
                    lines.extend([f'  br i1 {allowed}, label %allowed{ins.pc}, label %denied{ins.pc}',
                                  f'denied{ins.pc}:'])
                    write('error', '2')
                    write('fault_address', target)
                    lines.extend(['  br label %unwind', f'allowed{ins.pc}:'])
                return_address = code_base + functions[name]['address'] + ins.pc + ins.size
                address = stack_address(depth - 8)
                lines.append(f'  store i64 {return_address}, ptr {address}, align 1')
                write('sp', stack_offset(depth - 8))
                lines.append(f'  call void {native}(ptr %cpu, ptr %guest, ptr %stack, i64 {return_address})')
                if indirect_mode:
                    good = emit(f'icmp eq i64 {read("error")}, 0')
                    lines.extend([f'  br i1 {good}, label %returned{ins.pc}, label %unwind',
                                  f'returned{ins.pc}:'])
                guard(emit(f'icmp eq i64 {read("sp")}, {stack_offset(depth)}'))
            elif ins.op == 'ret':
                guard(emit(f'icmp eq i64 {read("sp")}, {entry_sp}'))
                guard(emit(f'icmp eq i64 {read("rbx")}, {entry_rbx}'))
                guard(emit(f'icmp eq i64 {read("rbp")}, {entry_rbp}'))
                address = stack_address(0)
                token = emit(f'load i64, ptr {address}, align 1')
                guard(emit(f'icmp eq i64 {token}, %expected'))
                write('sp', stack_offset(8))
                lines.append('  ret void')
                continue
            write('sp', stack_offset(sp))
        if indirect_mode:
            lines.append('unwind:')
            write('rbx', entry_rbx)
            write('rbp', entry_rbp)
            write('sp', stack_offset(8))
            lines.append('  ret void')
        lines.extend(['fault:', '  call void @llvm.trap()', '  unreachable', '}'])
        module.append('\n'.join(lines))
    return '\n\n'.join(module), analyses
