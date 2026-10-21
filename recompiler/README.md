# P0 CPU AOT experiment (Apple Silicon)

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

## Contract and evidence

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
