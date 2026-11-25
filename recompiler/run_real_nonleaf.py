#!/usr/bin/env python3
"""Compare an allowlisted local PS4 wrapper on Rosetta and native ARM64 AOT."""
import argparse
import json
import platform
import struct
import subprocess
import tempfile
from pathlib import Path

from audit_real_cpu import digest, function_ranges, mapped_offset
from cpu_state import c_layout_checks
from link_modules import module
from run_state_stack import whole_native_bridge
from run_simd import VENDOR, softfloat_inputs
from state_stack_lift import CODE_BASE, decode, lift

ROOT = Path(__file__).resolve().parent
MODULE_SHA = '3b8eb4d5a5c5a7b381d8d0610077e6cd404c29695a686274802f6b2737f6bf22'
FUNCTION_OFFSET = 0x2e0d0
COND_INIT = ('2Tb92quprl0', ('libkernel', 1), ('libkernel', 257))
RETURN_OFFSET = 0x80000
RIP_CALL_OFFSET = 0x1000
RIP_CALLEE_OFFSET = 0x1200
RIP_SLOT_OFFSET = 0x800
TEST_FLAGS = 0x8c5

IMPORT_THUNK = """
.globl _ss_native_import
_ss_native_import:
    # The bridge saves its host stack and private state in xmm14/xmm15.
    movq %rsp, %xmm13
    movq %xmm14, %rsp
    subq $40, %rsp
    movq %xmm13, 0(%rsp)
    movq %xmm10, 8(%rsp)
    movq %xmm14, 16(%rsp)
    movq %xmm15, 24(%rsp)
    call _ss_native_import_c
    movq 8(%rsp), %xmm10
    movq 16(%rsp), %xmm14
    movq 24(%rsp), %xmm15
    movq 0(%rsp), %rsp
    ret
"""


def selection(path):
    parsed = module(path)
    if parsed['sha256'] != MODULE_SHA:
        raise ValueError('libSceFios2.prx version outside the differential fixture')
    elf, headers = parsed['elf'], parsed['ph']
    ranges, _, _ = function_ranges(elf, headers)
    matches = [(size, offset) for address, size, offset in ranges if address == FUNCTION_OFFSET]
    if len(matches) != 1:
        raise ValueError('expected one matching FDE')
    size, file_offset = matches[0]
    code = elf[file_offset:file_offset + size]
    decoded = decode(code, real=True)
    call, = (i for i in decoded if i.op == 'call')
    lea, = (i for i in decoded if i.op == 'lea' and i.reg == 2 and i.memory.rip_relative)
    trap, = (i for i in decoded if i.op == 'ud2')
    store, = (i for i in decoded if i.op == 'memory' and i.memory.op == 'store')
    name_address = FUNCTION_OFFSET + lea.pc + len(lea.raw) + lea.memory.displacement
    start = mapped_offset(headers, name_address, 1)
    name_bytes = elf[start:elf.index(0, start, start + 128) + 1]
    mapped_offset(headers, name_address, len(name_bytes))

    plt_address = FUNCTION_OFFSET + call.target
    start = mapped_offset(headers, plt_address, 6, executable=True)
    plt = elf[start:start + 6]
    if plt[:2] != b'\xff\x25':
        raise ValueError('expected a RIP-relative PLT jump')
    got_address = plt_address + len(plt) + struct.unpack_from('<i', plt, 2)[0]
    mapped_offset(headers, got_address, 8)
    relocations = [(kind, index, addend) for target, kind, index, addend in parsed['relocs']
                   if target == got_address]
    if len(relocations) != 1:
        raise ValueError('expected one relocation for the PLT slot')
    kind, index, addend = relocations[0]
    symbol = parsed['symbols'][index]
    if kind != 7 or addend or symbol['section'] or symbol['identity'] != COND_INIT:
        raise ValueError('PLT slot is not the expected libkernel JUMP_SLOT')

    offsets = dict(FUNCTION_OFFSET=FUNCTION_OFFSET, PLT_OFFSET=plt_address, GOT_OFFSET=got_address,
                   NAME_OFFSET=name_address, TRAP_OFFSET=FUNCTION_OFFSET + trap.pc,
                   STORE_OFFSET=FUNCTION_OFFSET + store.pc,
                   CONTINUATION_OFFSET=FUNCTION_OFFSET + call.pc + len(call.raw))
    return code, plt, name_bytes, call.pc, offsets


def generated_sources(scratch, code, plt, name, call_pc, offsets):
    # Backward RIP-relative data references, with a bounded indirect CALL.
    move = b'\x48\x8b\x05' + struct.pack('<i', RIP_SLOT_OFFSET - RIP_CALL_OFFSET - 7)
    call = b'\xff\x15' + struct.pack('<i', RIP_SLOT_OFFSET + 8 - RIP_CALL_OFFSET - 13)
    scalar = bytes.fromhex(
        '49 b8 1032547698badcfe '  # movabs r8, 0xfedcba9876543210
        '46 8d 4c40 ff '          # lea r9d, [rax + r8*2 - 1]
        '48 83 f0 80 '            # xor rax, -128
        '49 81 c0 00000080 '      # add r8, -2147483648
        '48 c7 07 ffffffff '      # mov qword [rdi], -1
        '48 83 3f ff 74 02 0f0b '  # cmp qword [rdi], -1; je over UD2
        '48 3b 07 72 02 0f0b '     # cmp rax, [rdi]; jb over UD2
        'f6 07 01 75 02 0f0b '     # test byte [rdi], 1; jne over UD2
        '48 b9 0100000000000080 '  # movabs rcx, 0x8000000000000001
        '48 d1 e1 70 02 0f0b '     # shl rcx, 1; jo over UD2
        '48 c1 e9 01 '             # shr rcx, 1
        '48 ba 0100000000000080 '  # movabs rdx, 0x8000000000000001
        '48 c1 fa 3f '             # sar rdx, 63
        '48 89 ce 48 d1 ce '       # mov rsi, rcx; ror rsi, 1
        '48 c1 c6 02 '             # rol rsi, 2
        '49 ba 1122334455667788 '  # movabs r10, 0x8877665544332211
        '41 c1 e2 20 '             # shl r10d, 32 (masked count zero)
        '45 0f b6 da '             # movzx r11d, r10b
        '48 83 f8 ff b1 40 '      # cmp rax, -1; mov cl, 64
        '49 d3 ea 72 02 0f0b '     # shr r10, cl; masked zero count preserves CF
        'b1 41 49 d3 e2 '         # mov cl, 65; shl r10, cl
        '48 d3 ce '               # ror rsi, cl
        '66 2e 0f1f 8400 00000000 ' # multi-byte NOP
        'c5 fc 28 57 20 '          # vmovaps ymm2, [rdi + 32]
        'c4 e1 7c 11 57 40 '       # vmovups [rdi + 64], ymm2 (three-byte VEX)
        'c5 f9 10 57 20 '          # vmovupd xmm2, [rdi + 32], clearing upper YMM
        'c5 fc 11 57 60 '          # vmovups [rdi + 96], ymm2
        'c5 fa 10 57 20 '          # vmovss xmm2, [rdi + 32]
        'c5 fa 11 97 80000000 '    # vmovss [rdi + 128], xmm2
        'c5 fb 10 57 28 '          # vmovsd xmm2, [rdi + 40]
        'c5 fc 11 97 a0000000 '    # vmovups [rdi + 160], ymm2
        'c5 fc 10 57 20 '          # vmovups ymm2, [rdi + 32]
        'c5 ec 58 57 20 '          # vaddps ymm2, ymm2, [rdi + 32]
        'c5 fc 11 97 c0000000 '    # vmovups [rdi + 192], ymm2
        'c5 ec 59 57 20 '          # vmulps ymm2, ymm2, [rdi + 32]
        'c5 ec 5e 57 20 '          # vdivps ymm2, ymm2, [rdi + 32]
        'c5 ec 5c 57 20 '          # vsubps ymm2, ymm2, [rdi + 32]
        'c5 fc 11 97 e0000000 '    # vmovups [rdi + 224], ymm2
        'c5 fb 10 97 00010000 '    # vmovsd xmm2, [rdi + 256]
        'c5 eb 58 97 00010000 '    # vaddsd xmm2, xmm2, [rdi + 256]
        'c5 fc 11 97 20010000 '    # vmovups [rdi + 288], ymm2
        '48 83 f8 ff '            # cmp rax, -1
    )
    rip_call = move + call + scalar + b'\xc3'
    rip_callee = b'\xc3'
    spec = {
        'fios_cond': {'address': FUNCTION_OFFSET, 'parts': [code.hex()],
                      'host_imports': {str(call_pc): offsets['PLT_OFFSET']}},
        'rip_call': {'address': RIP_CALL_OFFSET, 'parts': [rip_call.hex()],
                     'indirect_targets': {'7': ['rip_callee']}},
        'rip_callee': {'address': RIP_CALLEE_OFFSET, 'parts': [rip_callee.hex()]},
    }
    root_return = CODE_BASE + RETURN_OFFSET
    ir, functions, decoded, calls, _ = lift(spec, mapped=True, real=True,
                                           image_limit=RETURN_OFFSET, root_return=root_return)
    (scratch / 'nonleaf.ll').write_text(ir)
    (scratch / 'cpu_state_layout.h').write_text(c_layout_checks())
    bridge = whole_native_bridge(
        {n: functions[n] for n in ('fios_cond', 'rip_call')}, decoded, calls,
        flag_mask=lambda name: TEST_FLAGS if name == 'fios_cond' else 0x8d5, root_return=root_return)
    (scratch / 'original.s').write_text(bridge + IMPORT_THUNK)

    constants = dict(offsets, IMAGE_BASE=CODE_BASE, NAME_ADDRESS=CODE_BASE + offsets['NAME_OFFSET'],
                     RETURN_ADDRESS=root_return, RETURN_OFFSET=RETURN_OFFSET,
                     RIP_CALL_OFFSET=RIP_CALL_OFFSET, RIP_CALLEE_OFFSET=RIP_CALLEE_OFFSET,
                     RIP_SLOT_OFFSET=RIP_SLOT_OFFSET)
    header = [f'#define {key} UINT64_C({value})' for key, value in constants.items()]
    header += [f'#define COND_INIT_NID "{COND_INIT[0]}"']
    arrays = dict(module_function=code, module_plt=plt, module_name=name,
                  rip_call_code=rip_call, rip_callee_code=rip_callee)
    for key, binary in arrays.items():
        header += [f'static const unsigned char {key}[] = {{' + ', '.join(map(str, binary)) + '};']
    (scratch / 'real_nonleaf_image.h').write_text('\n'.join(header) + '\n')


def run(game, out):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ValueError('use native ARM64 Python on Apple Silicon')
    out.mkdir(parents=True, exist_ok=True)
    report = out / 'verification.json'
    artifact = out / 'real-nonleaf-arm64.o'
    artifact.unlink(missing_ok=True)
    report.write_text(json.dumps({'status': 'incomplete'}) + '\n')
    code, plt, name, call_pc, offsets = selection(game / 'sce_module/libSceFios2.prx')
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        scratch = Path(tmp)
        generated_sources(scratch, code, plt, name, call_pc, offsets)
        common = ['-O2', '-Wall', '-Wextra', '-Werror', '-Wno-ignored-attributes', '-DBB_LOW_HEAP_IMPL',
                  '-I', scratch, '-I', ROOT, '-I', ROOT.parent / 'src', ROOT / 'real_nonleaf_harness.c',
                  ROOT / 'state_regions.c', ROOT.parent / 'src/runtime_mutex.c']
        subprocess.run(['clang', '-arch', 'x86_64', '-DORIGINAL', *common, scratch / 'original.s',
                        '-o', scratch / 'original'], check=True, timeout=60)
        subprocess.run(['clang', '-arch', 'arm64', '-O2', '-Wno-override-module', '-c',
                        scratch / 'nonleaf.ll', '-o', scratch / 'nonleaf.o'], check=True, timeout=60)
        vendor = json.loads((VENDOR / 'manifest.json').read_text())
        subprocess.run(['clang', '-arch', 'arm64', '-std=c11', *softfloat_inputs(vendor),
                        *common, scratch / 'nonleaf.o', '-Wno-unused-parameter', '-Wno-unused-label',
                        '-o', scratch / 'arm64'], check=True, timeout=60)
        results = {}
        for name, arch in (('original', 'x86_64'), ('arm64', 'arm64')):
            proc = subprocess.run(['/usr/bin/arch', '-' + arch, scratch / name],
                                  capture_output=True, timeout=60)
            (out / (name + '.stdout.log')).write_bytes(proc.stdout)
            (out / (name + '.stderr.log')).write_bytes(proc.stderr)
            proc.check_returncode()
            results[name] = proc.stdout
        if results['original'] != results['arm64'] or len(results['original'].splitlines()) != 5:
            raise ValueError('differential snapshot mismatch; inspect stdout logs')
        if proc.stderr != b'ARM64 checked failures: 7\n':
            raise ValueError('missing ARM64 fault-check confirmation')
        architecture = subprocess.check_output(['lipo', '-archs', scratch / 'nonleaf.o'],
                                               text=True, timeout=60).strip()
        if architecture != 'arm64':
            raise ValueError('expected an ARM64 Mach-O object')
        (scratch / 'nonleaf.o').replace(artifact)
    report.write_text(json.dumps({
        'status': 'verified', 'reference': 'original x86_64 under Rosetta',
        'candidate': 'ARM64 object from LLVM IR, linked with the macOS runtime mutex implementation',
        'module_sha256': MODULE_SHA, 'function_sha256': digest(code), 'function_bytes': len(code),
        'offsets': {key.lower(): hex(value) for key, value in offsets.items()},
        'import': {'name': 'scePthreadCondInit', 'identity': COND_INIT},
        'artifact': {'name': artifact.name, 'arch': architecture, 'sha256': digest(artifact.read_bytes())},
        'matched_real_cases': 4, 'matched_synthetic_cases': 1, 'arm64_fault_cases': 7,
        'scope': 'bounded isolated fixture with normalized handles and ABI-defined observable state',
    }, indent=2) + '\n')
    print(f'4 real cases and 1 synthetic case match Rosetta; 7 ARM64 fault cases passed. {report}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'out/cpu-real-nonleaf')
    args = parser.parse_args()
    try:
        run(args.game_dir, args.out.resolve())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
