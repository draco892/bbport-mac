# ARM64 CPU experiment: register-only SSE/SSE2 correctness

Updated 2026-11-13. This completes a **bounded SIMD/FP correctness increment**
within P1. It does not complete the CPU backend, select the production execution
strategy or establish game compatibility. No game files or gameplay tests are
used by this experiment.

## Run

```sh
python3 recompiler/run_simd.py
# The same differential corpus, plus native UndefinedBehaviorSanitizer:
python3 recompiler/run_simd.py --sanitize
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
```

Requires native ARM64 Python 3.11+, Xcode/Command Line Tools and Rosetta for the original
x86 development oracle and AOT x86 comparison. The AOT ARM64 executable itself
runs natively. There are no network downloads: the required SoftFloat source
subset is vendored with its license, upstream archive identity and per-file hashes.
The runner verifies those hashes before compilation.

Outputs stay under ignored `out/recompiler-simd/`; `--out PATH` preserves a
separate run. `--random-count N` controls the additional seeded base states.
Reports start incomplete and are marked passed only after all checks finish.
Failures retain a failed report and diagnostics rather than a stale success.

## Explicit contract

The input is a known synthetic function containing only whitelisted register
instructions and a final RET. The entire function is decoded before IR emission.
XMM0–XMM15 are fully initialized inputs and fully observable outputs. The
shared state also contains GPRs, RIP and RFLAGS; this SIMD path preserves those
fields. See [the CPU-state ABI](CPU_STATE.md) for layout and exact scope. MXCSR is
explicit guest state, with all six exceptions masked. All four rounding modes,
all four DAZ/FTZ combinations and sticky exception flags are supported. Unmasked
exceptions and reserved MXCSR bits return status 1 without changing registers,
MXCSR or reserved state. Unsupported code is rejected before compilation.

The C state is 416 bytes: sixteen 64-bit GPRs, sixteen 128-bit XMM registers,
64-bit RIP/RFLAGS, 32-bit MXCSR/status and a reserved 64-bit sentinel. The harness checks its layout, leading/trailing guards
and the sentinel. State pointers obey the C structure's alignment contract.
Original x86 wrappers load the same state, execute the actual fixture bytes,
capture all sixteen XMM registers and MXCSR, and restore the host's previous
MXCSR. The oracle also checks hardware CF/PF/AF/ZF/SF/OF preservation; stored
GPR/RIP/RFLAGS preservation is checked independently by the harness. AOT starts
from the same state, without executing x86 bytes.

Integer support:

- Register MOVDQA/MOVDQU copies.
- Wrapping PADDB/W/D/Q and PSUBB/W/D/Q.
- PAND, PANDN, POR and PXOR over 128 bits.
- PCMPEQB/W/D and signed PCMPGTB/W/D, producing full-width lane masks.
- Immediate PSLLW/D/Q, PSRLW/D/Q and PSRAW/D. Oversized logical shifts produce
  zero; arithmetic shifts saturate to the sign. Counts are not scalar-x86 masked
  counts, and LLVM never receives an out-of-range shift count.
- PSHUFD, including lane reversal, repetition, identity and cross-register copies.
- Signed and unsigned saturating PADDSB/W, PADDUSB/W, PSUBSB/W and PSUBUSB/W.
- PUNPCKLBW/WD/DQ/QDQ and PUNPCKHBW/WD/DQ/QDQ, interleaving the selected
  halves of the old destination and source in that order.
- PACKSSWB, PACKSSDW and PACKUSWB. All consume signed input lanes, including
  PACKUSWB; negative words become zero rather than the maximum unsigned byte.
- PMULLW, PMULHW, PMULHUW and PMADDWD. Signed and unsigned high products remain
  distinct; PMADDWD wraps its exceptional `(-32768)^2 + (-32768)^2` result to
  `0x80000000`. Operands may be identical; all four XMM0/XMM1 pairs are tested
  for each new opcode, along with compound pack/unpack/multiply sequences.

FP support:

- ADD, SUB, MUL, DIV and SQRT in packed PS/PD and scalar SS/SD forms.
- Scalar instructions preserve all unaffected destination bits; packed forms
  evaluate all lanes. SQRT observes the source lanes, not the old destination.
- Binary32/binary64 finite values, signed zeros, infinities, quiet/signaling NaNs,
  NaN payload propagation, subnormal inputs/results, exact/inexact rounding,
  overflow, underflow and exception-priority cases are compared bit for bit.
- DAZ flushes subnormal inputs to signed zero. FTZ flushes tiny results and reports
  underflow/precision, including exact subnormal results. The normal/subnormal
  boundary follows SSE's tininess decision after significand rounding with an
  unbounded exponent, before subnormal rounding. A boundary result that rounds up
  to the smallest normal in gradual mode can still require flushing under FTZ.

## Implementation and isolation

`recompiler/simd_lift.py` lowers integer vectors to LLVM integer operations.
FP lanes call `simd_fp.c`, an integer-only adapter around Berkeley SoftFloat 3e's
`8086-SSE` specialization. This avoids assuming that native ARM floating point
has identical NaN, subnormal and exception behavior. The adapter translates
rounding controls and exception flags, handles DAZ/FTZ and denormal-operand
priority, and saves/restores SoftFloat's thread-local environment per operation.
The FTZ boundary check uses exact integer power-of-two operand scaling and
re-evaluation in a normal exponent range, preserving the original flags.

The harness seeds a nondefault host environment and asserts preservation after
every invocation: hardware MXCSR on x86, FPCR/FPSR on ARM64. This is host-state
isolation evidence, not general callback, signal or cross-thread validation.
The expanded tests caught an ARM-specific issue: NEON saturation instructions
selected by LLVM set sticky FPSR.QC, unlike SSE2's unchanged MXCSR. Generated
functions now call opaque native save/restore helpers around all input loads,
computations and output stores. ARM64 preserves FPSR; x86 preserves MXCSR.
FPCR is never modified. The harness alternates the initial ARM QC bit between
clear and set, verifying both absence of leakage and preservation of prior QC.
This boundary adds correctness overhead; it is not a production optimization.
No `fast-math`, native FP IR, approximate square roots or fused operations are
used. This software correctness path makes no performance claim.

The common state is now used by SIMD. The previous scalar integer, memory,
stack, indirect-call and callback experiments still use their restricted layouts.
Combining their execution contracts and migrating them to the shared state remains
open; the struct alone does not establish full CPU semantics or a loader.

## Physical Apple Silicon evidence

The default corpus contains 1,250 binary32/binary64 edge pairs, 539 integer
boundary pairs, 256 seeded random base states, 30 dedicated FP known-answer cases
and 10 literal integer known-answer cases. Each is exercised with four
rounding modes, four DAZ/FTZ combinations and two initial sticky-flag patterns:
**66,720 base/control input states**, plus 1,280 inputs repeating the explicit
answers on XMM8/XMM15: **68,000 total states** across **780 fixtures**. The 542
new register fixtures include all 256 copy pairs, remapped versions of every
previous fixture and oversized shifts on all registers. The integer boundaries cover
signed/unsigned limits and the byte/word thresholds used by narrowing packs.

| Check | Result |
| --- | --- |
| Original x86 vs AOT x86-64 | 53,040,000 complete state snapshots, zero differences |
| Original x86 vs AOT ARM64 | 53,040,000 complete state snapshots, zero differences |
| Explicit known-answer snapshots | 2,560 passed per executable |
| Independent Python integer model vs original x86 | 1,963,204 selected state snapshots passed |
| Invalid MXCSR modes | 4,680 rejected, with unchanged state except status, per AOT backend |
| Host FP environment, state guards and reserved sentinel | Preserved at every tested invocation |
| Combined CPU static acceptance/rejection suite | 59 tests passed, including the GPR increment |
| Native ARM64 UndefinedBehaviorSanitizer | Full 53,040,000-snapshot corpus passed; zero differences or sanitizer reports |

Known answers cover ties, cancellation and signed zero, division by zero,
invalid results, exact and inexact underflow, overflow, square roots, NaN
priority and both sides of the FTZ normal/subnormal boundary. Upper scalar lanes
contain distinct signaling-NaN/sentinel patterns, so their preservation and lack
of unintended exceptions are observable. Mixed packed lanes exercise sticky
exception accumulation. Compound fixtures verify sequencing and reinterpretation
between integer and FP operations.

The independent integer model samples at least one control mode from every base
case, plus varied controls and all modes of the first base. Its count is not the
full differential corpus count. The development oracle is original x86 code
executed under Rosetta, not measurements on a physical Intel processor. Explicit
known answers provide an additional check, not a complete independent IEEE proof.

`verification.json` records commands, compiler, source/vendor/input/result hashes,
counts and outcomes. `inputs.bin` and `inputs.json` retain every exact input;
`known-answers.json` retains independent expected snapshots. Generated LLVM IR,
original x86 assembly, full binary results and build/run diagnostics are retained.

## Open boundaries

- No general decoder, guest memory accesses, address mapping, loads/stores from
  arbitrary guest pointers, stack/calls, branches or guest execution entry.
- YMM/AVX, x87, SIMD comparisons/conversions, min/max, shuffle families
  beyond PSHUFD and the listed unpack forms, and other SSE extensions remain unsupported.
- Unmasked FP traps, guest exception delivery, signal/fault integration and
  execution semantics for the stored guest GPR/RFLAGS remain open. Rejection is not exception emulation.
- Atomics, x86 memory ordering, general stack addressing, indirect targets and
  callback lifecycle retain the open gates in [P1](CPU_BACKEND_P1.md).
- The software FP helper is a correctness reference, not a decision to use it for
  all production execution. Native optimization requires the same observable
  semantics and differential evidence.
- Real game/module instruction coverage, runtime integration and gameplay
  validation remain separate work. The user will perform actual game tests.

References: [Intel SDM volume 1, especially chapters 10/11 and appendix D](https://cdrdv2-public.intel.com/789574/253665-sdm-vol-1.pdf),
[Berkeley SoftFloat](https://www.jhauser.us/arithmetic/SoftFloat.html),
[LLVM integer vector operations](https://llvm.org/docs/LangRef.html#vector-operations),
[Intel instruction reference, including PACKUSWB and PMADDWD](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf),
[Arm saturation and QC semantics](https://documentation-service.arm.com/static/5f3e8d48b13d4764d4613a13).

The common-state run and all four matching result hashes are retained in
`out/recompiler-cpu-state-v1/verification.json`. Its identical full snapshots
are retained once in a lossless gzip archive, with the path and compressed and
uncompressed hashes recorded under `result_artifacts`; the archive round trip
was verified before the raw copies were removed. Reproduce the test with:

```sh
python3 recompiler/run_simd.py --sanitize --out out/recompiler-cpu-state-v1
```
