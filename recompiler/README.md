# CPU AOT experiments (Apple Silicon)

This is a **new, deliberately restricted experiment** for issue #9. It does not
recover or reproduce the historical Linux prototype described in
[`CPU_RECOMPILATION_ANALYSIS.ru.md`](../docs/CPU_RECOMPILATION_ANALYSIS.ru.md), and
does not translate Bloodborne. The historical `recompiler/` sources were absent
from this checkout and its available Git history before this experiment was added.

## Reproduce

On an Apple Silicon Mac with native Python 3 and Xcode/Command Line Tools:

```sh
python3 recompiler/run.py
python3 -m unittest discover -s tests -p 'test_cpu_lift.py' -v
```

Rosetta is required **only for the development reference runs** in this experiment.
The generated `aot-arm64` executable is ARM64 and executes without Rosetta. This
does not establish that the whole game, preparation pipeline or runtime can do so.
The script explicitly launches each executable with its expected architecture.

`out/recompiler-p0/` contains generated LLVM IR, the original x86 bytes as assembly,
a C harness, the exact input corpus, build logs, three result files, three Mach-O
executables and `verification.json`. The report records source hashes, compiler,
seed and build commands. It is marked incomplete at the start of each run; a
failure cannot leave a previous success report in place. Generated outputs stay
under ignored `out/`; no game files are needed or included.

## P0 leaf contract and evidence

- Input registers: RDI and RSI (two unsigned 64-bit values); observable output: RAX.
- Only exact whitelisted encodings: MOV from RDI to RAX; ADD/SUB/XOR/AND/OR of
  RSI into RAX; immediate SHL/SHR/SAR of RAX; corresponding 32-bit forms; final RET.
- Arithmetic wraps at its operand width. EAX writes zero the upper half of RAX.
  Shift counts are masked to the x86 operand width before generating LLVM shifts.
- No stack accesses, guest memory, branches, calls, SIMD, exceptions, TLS or atomics.
  Flags and other registers are not observable outputs under this contract. Flag
  consumers are rejected. Unsupported bytes, missing RET and trailing bytes fail.
- The inputs are hand-authored synthetic x86 instruction bytes, not recovered game
  functions. This whitelist is not a substitute for Zydis or a full decoder.

The harness executes the same original bytes on x86-64, then the lifted LLVM IR
compiled for x86-64 and ARM64. Each translated backend is compared with the
original results. The corpus has 225 boundary input pairs plus 4,096 seeded random
pairs, across 13 fixtures: **56,173 RAX comparisons per translated backend**.
Negative tests check rejection of code outside the contract.

This validates the smallest translation/compile/native-execution loop. It says
nothing about game instruction coverage, full ABI correctness, x86 memory ordering
or gameplay performance. Next steps and baseline prerequisites are in
[`CPU_BACKEND_P0.md`](../docs/CPU_BACKEND_P0.md).

## Bounded memory and forward branches (early P1 validation)

```sh
python3 recompiler/run_memory.py
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
```

This separate experiment extends validation to a 64-byte memory region and
forward control flow. It preserves the P0 leaf experiment and its corpus.

- RDI holds an immutable pointer to the test region, RSI a scalar input. RAX is
  returned; all 64 bytes of memory are observable outputs. Two 16-byte guards are
  independently checked for corruption and included in the differential output.
- Supported memory operands are `[rdi]` and `[rdi+disp8]`, with the whole access
  statically inside the region. Loads and stores use LLVM alignment 1. The corpus
  exercises 8/16/32/64-bit accesses, zero/sign extension, partial stores, unaligned
  accesses, overlapping stores and the last valid 64-bit access in the region.
- The instruction subset includes MOV, wrapping ADD/SUB/XOR, CMP, TEST, RET, short
  forward JMP and ten short conditional branches after 32/64-bit CMP. Only JE/JNE
  after TEST are accepted. CMP operands are captured when CMP runs; later MOVs do
  not change the comparison. Arithmetic flag consumers remain unsupported.
- The whole fixture is decoded and its forward graph checked before IR emission.
  Every edge must target an instruction boundary. Every instruction must be
  reachable. RAX and comparison state must be defined on **all** incoming paths;
  incompatible flag states at joins are rejected when consumed.
- Negative tests reject unsupported addressing, out-of-range memory, undefined
  state, clobbered flags, backward/out-of-function/mid-instruction branches,
  unreachable trailing code, calls, atomics and TLS instructions.

`out/recompiler-memory/` contains the generated LLVM IR, original x86 bytes,
harness, exact inputs, compiler/run logs, result files, executables and a
`verification.json` report. Failed/incomplete runs cannot retain a success report.
As with P0, Rosetta is the development reference only; the translated ARM64
executable runs natively.

The 47 fixtures run on 484 boundary input pairs plus 1,024 seeded random pairs:
**70,876 return/memory comparisons per translated backend**, with zero mismatches
on Apple Silicon. Original x86 bytes are compared with LLVM AOT compiled for both
x86-64 and ARM64. Conditional fixtures give their paths different memory effects,
so correctness is not inferred solely from an equal return value.

These are synthetic functions with a direct host pointer representing a bounded
test region. This is not a guest virtual-address mapper, full CPU-state model,
general x86 decoder, stack/call translator or concurrency/memory-ordering test.
The subset and known function boundaries are supplied explicitly. No game
coverage, runtime compatibility or speed improvement is established. Remaining
P1 work is tracked in [`CPU_BACKEND_P1.md`](../docs/CPU_BACKEND_P1.md).
