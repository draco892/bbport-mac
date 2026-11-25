# Common CPU-state ABI v1

Updated 2026-11-25. Work for [issue #9](https://github.com/bmy/bbport-mac/issues/9).
The common state definition is now consumed by the register-only SIMD experiment,
the [32/64-bit GPR/flag experiment](CPU_BACKEND_GPR.md) and the
[checked guest-memory path](CPU_BACKEND_STATE_MEMORY.md), and
[stack/direct calls](CPU_BACKEND_STATE_STACK.md). The earlier forward-control-flow,
indirect-call and callback paths still need migration. General CPU-state integration
remains open.

## Layout

`recompiler/cpu_state.h` defines `BbCpuState`. `cpu_state.py` supplies the binary
format and the offsets used by LLVM and the x86 oracle. Every harness compilation
includes generated C assertions comparing every actual C field offset, structure
size and alignment against the Python/LLVM contract, on both architectures.

| Field | Byte offset | Size | SIMD contract |
| --- | --- | --- | --- |
| GPRs | 0 | 128 | Preserve all 16 stored values |
| XMM0–XMM15 | 128 | 256 | Fully initialized and observable; supported SSE/SSE2 operations |
| Guest RIP | 384 | 8 | Preserve the explicit guest address |
| Guest RFLAGS | 392 | 8 | Preserve; instructions in this subset do not change flags |
| MXCSR | 400 | 4 | Explicit guest controls and sticky flags |
| Status | 404 | 4 | 0 for success; 1 for unsupported FP controls |
| Reserved sentinel | 408 | 8 | Preserve |

The binary state is little-endian, **416 bytes**, with 8-byte C alignment. GPR
indices use x86 encoding order: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8–R15.
Guest addresses and register values are integers, not native pointers. There is
no automatic RIP advancement in the older leaf-function contracts. Stack mode
tracks active guest RIP, direct-call targets and checked guest return addresses.

The struct itself provides storage, with execution semantics supplied by each
translator. In the SIMD path, the C harness checks preservation of GPR/RIP/RFLAGS, along
with the guards and sentinel, after every invocation. In the original x86
oracle, each fixture also runs with input CF/PF/AF/ZF/SF/OF loaded into actual
hardware flags, and checks their preservation before wrapper arithmetic can
alter them. The AOT path leaves the stored guest RFLAGS unchanged. This does not
validate instructions that produce or consume arithmetic flags. The separate
GPR path now validates a bounded 32/64-bit arithmetic and CMOV subset; DF, traps
and privileged controls remain outside both contracts.

## Extended registers

All previously supported SSE/SSE2 operations now accept XMM0–XMM15. The bounded
decoder accepts one canonical REX prefix immediately after the optional mandatory
66/F2/F3 prefix. REX.R extends the ModR/M register operand, and REX.B extends its
register r/m operand. The immediate-shift opcode group stays three bits; only
REX.B extends the shifted register. REX.R on an immediate-shift group, REX.W,
REX.X, repeated/misplaced prefixes and memory operands fail closed. Some of these
prefix combinations can be ignored by real x86 hardware; rejecting them is an
explicit restriction of the experiment, not a claim that they are illegal x86.

LLVM loads and stores the entire XMM bank through the common layout. Original
x86 wrappers load and capture all sixteen actual XMM registers. The corpus gives
the other registers distinct sentinel lanes, making missing extension bits and
accidental changes to unused registers observable. Legacy scalar operations
preserve their destination's upper lanes, including on XMM8–XMM15.

`simd_register_fixtures.json` adds 542 fixtures to the previous 238:

- All 238 previous fixtures remapped from XMM0/XMM1 to XMM8/XMM15, covering
  integer, packed/scalar FP, aliasing, immediate and compound operations.
- All 256 register-copy source/destination pairs, including self copies and
  XMM7/XMM8 transitions, checking independent REX.R and REX.B selection.
- Three oversized shift patterns on each of the 16 registers.

Every one of the 1,280 previous explicit known answers is also repeated with its
exact operands in XMM8/XMM15, while checking preservation of all other fields.
The Python integer model observes all 16 registers and the entire common state.

## Reproduce

```sh
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
python3 recompiler/run_simd.py --sanitize --out out/recompiler-cpu-state-v1
```

Requires native ARM64 Python 3.11+, Xcode/Command Line Tools, and Rosetta for
the development x86 oracle.

The default corpus now has **780 fixtures × 68,000 states = 53,040,000 complete
state snapshots per backend**, including 2,560 explicit known answers and 4,680
invalid-mode checks per AOT backend. Native ARM64 UBSan runs the same corpus.
The 2026-11-13 run passed with zero differences across original x86, AOT x86,
AOT ARM64 and AOT ARM64 UBSan. All four result SHA-256 hashes are identical.
The independent Python integer model passed **1,963,204** selected complete
snapshots; the combined CPU acceptance/rejection and layout suite now passes
**89 tests**, including the subsequent GPR, guest-memory and stack increments.
See `out/recompiler-cpu-state-v1/verification.json` for the measured outcomes,
compiler commands, source hashes, state offsets and result hashes. Snapshots now
include 416 bytes rather than 48: the four uncompressed result files total about
88 GB. Large result hashes are computed as streams rather than loading a whole
file into Python memory.

After verification, the identical raw results were retained once in a lossless
gzip archive, indexed by content hash under `result_artifacts` in that report.
Both the compressed hash and original snapshot hash are recorded. A complete
gzip round trip was checked before deleting the four raw copies. Re-running the
test command produces fresh uncompressed files.

The checked memory path executes scalar GPR/flag operations and guest loads/stores
in this state; stack mode now adds PUSH/POP, frames and direct CALL/RET with a
separate 512-byte mapping. Forward-control-flow, indirect calls and callbacks
still need migration. Remaining work includes GPR/flag-producing instruction
coverage beyond the bounded arithmetic subset, combined memory/call/SIMD execution,
x87/AVX/segment state, exceptions, atomics and real game-function coverage.
Actual game testing stays with the user.

Encoding reference: [Intel instruction format and REX prefix placement](https://cdrdv2-public.intel.com/843829/325383-sdm-vol-2abcd-dec-24.pdf).
