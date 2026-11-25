# Common-state GPR and arithmetic-flag correctness

Updated 2026-11-25. Part of [issue #9](https://github.com/bmy/bbport-mac/issues/9).
This adds executable GPR/flag semantics to the same 416-byte state already used
by SIMD. It is a bounded synthetic experiment; forward-control-flow/indirect-call/callback migration,
general instruction coverage and production runtime integration remain open.

## Supported contract

The complete function is decoded before LLVM emission. Inputs are all sixteen
64-bit guest GPRs and RFLAGS. All GPRs and arithmetic flags are observable outputs.
Other state fields, including XMM0–15, RIP, MXCSR and the reserved sentinel, must
remain bitwise unchanged; status becomes zero. RSP and RDI are ordinary guest
integers. Guest register values are never cast into native pointers or used as
the ARM64 host stack. RIP is preserved by this synthetic leaf contract.

Supported operations in 8-, 16-, 32- and 64-bit register forms unless specified:

- MOV, ADD, ADC, SUB, SBB, AND, OR, XOR, CMP and TEST.
- INC and DEC, preserving the incoming CF while updating other arithmetic flags.
- All sixteen CMOVcc conditions in 16-, 32- and 64-bit forms, consuming explicit guest CF/PF/ZF/SF/OF.
- Canonical REX.W/R/B selection of all GPRs, including R8–R15 and RSP.
- Straight-line instruction sequences, ending in one synthetic RET marker.

Byte and word writes preserve the upper destination bits. High byte AH/CH/DH/BH
forms are excluded. All 32-bit destination writes zero-extend into the full guest register. CMP and
TEST do not write their destination at all. A 32-bit CMOV zeroes the upper half
even when the condition is false; this is explicitly tested against actual x86.

CF, PF, AF, ZF, SF and OF are modeled as explicit integer bits. LLVM integer
operations do not rely on host condition codes. ADD/ADC/SUB/SBB compute carries
and borrows in 9/17/33/65-bit intermediates; arithmetic has no `nsw`/`nuw` assumptions.
Parity observes the low byte only. ADC/SBB consume incoming guest CF, and the
compound fixtures verify propagation between different registers.

AF after AND/OR/XOR/TEST is architecturally undefined. Both paths normalize it to
zero, rather than treating an observed Rosetta value as an architectural rule.
Per-fixture final defined-flag masks are retained in the report. MOV/CMOV preserve
the current flag state, and a later arithmetic instruction can define AF again.
Non-arithmetic RFLAGS bits are opaque preserved storage: this does not implement
DF/TF, privilege controls, traps or flag-loading instructions.

Unsupported high-byte operations, alternate opcode encodings, shifts, NEG,
multiply/divide, flag transfer, SETcc, branches, calls, memory operands, repeated
or noncanonical prefixes and trailing code fail closed. Some rejected encodings
are valid x86; rejection only describes the bounded experiment's contract.

## Development oracle and isolation

`run_gpr.py` creates wrappers which load all sixteen real x86 GPRs and install
only the six arithmetic status bits from the input. The exact fixture instruction
bytes execute inline, without the final RET marker. The wrapper captures every
GPR and hardware RFLAGS before normalizing undefined bits and restoring the host
ABI. Callee-saved GPRs are restored. Host scratch XMM12–15 retain the state pointer,
native SP and the guest RAX/RSP outputs; no global scratch buffer is used.

This arrangement allows fixtures to modify the real RSP and RDI without using
guest values as oracle pointers or dereferencing the guest stack. The original
oracle temporarily holds arbitrary guest data in hardware RSP: it is an isolated
development harness and provides no asynchronous-signal or unwind correctness
claim. Translated ARM64 code only reads and writes integer fields in `BbCpuState`.
This does not validate real guest CALL/RET or stack memory behavior.

The C harness independently checks both state guards, the sentinel, all XMMs,
RIP, MXCSR and non-arithmetic RFLAGS after every invocation. It seeds nondefault
host MXCSR on x86, and FPCR/FPSR on ARM, alternating FPSR.QC clear/set. Both native
host environments remain unchanged. All C/LLVM/Python state offsets and size are
checked against compiled C layout assertions on both architectures.

## Reproduce and evidence

Requires native ARM64 Python 3.11+, Xcode/Command Line Tools and Rosetta for the
development x86 oracle. No game assets or network downloads are needed.

```sh
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
python3 recompiler/run_gpr.py --sanitize
```

The default output is `out/recompiler-gpr/`; `--out PATH` selects another run and
`--random-count N` changes the additional seeded random inputs. Reports begin
incomplete, failures are marked failed, and success requires all checks below.

| Check | Result |
| --- | --- |
| Fixtures | 1,976, including 256 new 8/16-bit fixtures, all 512 original MOV pairs and 56 compound sequences |
| Input states | 5,718 |
| Original x86 vs AOT x86-64 | 11,298,768 complete snapshots, zero differences |
| Original x86 vs AOT ARM64 | 11,298,768 complete snapshots, zero differences |
| Native ARM64 UBSan | Same complete corpus passed, no differences or sanitizer findings |
| Explicit literal answers | 22 passed per executable |
| Independent Python integer model | 825,968 selected complete snapshots passed |
| Combined CPU acceptance/rejection/layout test suite, including memory and stack | 89 passed |

The corpus includes all pairs from sixteen integer edges under four initial flag
patterns, every low-byte value against seven carry/borrow boundaries with both
incoming carries, all 64 initial arithmetic-flag combinations, 1,024 seeded random
register banks and 22 explicit known answers. Sentinel/unique register patterns
expose unintended writes and wrong register selection. All sixteen CMOV conditions
and aliased operands are exercised; upper-half preservation/zeroing is observable.

The independent model uses signed-range checks for overflow and nibble arithmetic
for AF, separate from LLVM's bitwise formulas. It shares the strict decoder, so it
is additional evidence, not an independent decoder proof. The actual x86 bytes
under Rosetta remain the development oracle, not a physical Intel measurement.

`verification.json` records compiler commands, input and source hashes, state ABI,
defined-flag masks, counts and result hashes. All four full result hashes match.
Exact inputs, generated assembly/IR, known answers and diagnostics are retained.
Identical output snapshots are stored once in a gzip archive; its compressed and
uncompressed hashes are recorded under `result_archive`. A full gzip round trip
is verified before the raw copies are removed. The runner does this automatically.

The [checked memory increment](CPU_BACKEND_STATE_MEMORY.md) now combines guest
accesses and scalar instructions in this state. The [stack/direct-call path](CPU_BACKEND_STATE_STACK.md) also uses this layout
and the shared arithmetic lowerer for signed RSP adjustments. The raw GPR decoder
retains its register-only contract. The next integration work is to migrate
indirect-call/callback/control-flow contracts and combine them with SIMD. Full instruction
coverage, exceptions, atomics, game-function translation and runtime dispatch
remain open. Actual gameplay testing stays with the user.

Reference: [Intel instruction reference, especially ADC, CMOVcc and INC](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
