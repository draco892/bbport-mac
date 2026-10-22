# ARM64 CPU backend: early P1 correctness validation

Issue: [#9](https://github.com/bmy/bbport-mac/issues/9).
Updated: 2026-10-22. **P1 is not complete; CPU backend selection remains open.**
The game-dependent P0 baseline also remains open because the game is unavailable.

## Completed increment: bounded memory and forward control flow

The new `recompiler/memory_lift.py` experiment lifts a strict instruction subset
from hand-authored x86 bytes into LLVM IR. It accepts statically bounded accesses
to a 64-byte region, fixed-base addressing, 8/16/32/64-bit loads/stores and signed
loads, wrapping arithmetic, comparisons, conditional forward branches, multiple
returns and forward joins. Unsupported code fails before compilation.

The ABI for these fixtures is two inputs (RDI = region pointer; RSI = scalar) and
RAX output. RDI is immutable. The harness resets memory for each invocation,
initializes the region with deterministic data, checks two 16-byte guard areas
and emits both RAX and the full memory/guard snapshot for comparison. No guest
stack, guest address translation or runtime bridge is involved.

CFG validation rejects edges into instruction interiors or outside the function,
backward branches, unreachable instructions and paths using undefined RAX or
comparison state. At joins, RAX must be initialized on every incoming edge and
the flag interpretation must agree on all paths before a branch consumes it.
CMP/TEST operands are captured at comparison time; subsequent MOVs preserve that
state. Arithmetic invalidates supported comparison state, so branches cannot
silently reuse stale flags.

The supported CMP predicates are equality/inequality and signed/unsigned
less/greater (including equality), for both 32-bit and 64-bit operands. TEST
supports only zero/nonzero. This evaluates those branch semantics; it does not
materialize or validate all architectural RFLAGS bits.

## Reproduce and interpret the evidence

```sh
python3 recompiler/run_memory.py
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
```

Requires native ARM64 Python, Xcode/Command Line Tools and Rosetta for the x86
reference runs. The translated ARM64 executable itself is native. The default
output directory is `out/recompiler-memory/`; use `--out` to preserve another run.

Validation on physical Apple Silicon:

| Evidence | Result |
| --- | --- |
| Synthetic memory/control-flow fixtures | 47 |
| Boundary input pairs | 484 |
| Seeded random input pairs | 1,024 (`0xbb109`) |
| Original x86 vs LLVM AOT x86-64 | 70,876 output snapshots; zero differences |
| Original x86 vs LLVM AOT ARM64 | 70,876 output snapshots; zero differences |
| Guard corruption | None |
| Rejection tests for unsafe/undefined code | Passed |

Cases include unsigned carry/wrap boundaries, signed comparison overflow
boundaries, 32-bit zero extension, signed byte/word/dword loads, unaligned and
overlapping memory operations, both conditional outcomes and a two-path join.
Generated IR, exact original instruction bytes, inputs, outputs, compiler identity,
commands and source hashes are retained in the output directory. Each comparison
counts one invocation's RAX plus memory snapshot, not an instruction or individual
byte comparison. This is correctness evidence for the stated subset only.

## Remaining P1 gates

- [x] Integer leaf functions on physical ARM64 (the P0 experiment).
- [x] Bounded synthetic memory accesses and forward direct control flow.
- [ ] Guest stacks, direct calls and returns across translated functions.
- [ ] Indirect calls/jumps, code-address resolution and host/guest callbacks.
- [ ] Full observable guest register/flag state, beyond the current contracts.
- [ ] SIMD and floating-point semantics, rounding, NaNs and exceptional inputs.
- [ ] Atomics and an explicit strategy for x86 memory ordering on ARM64.
- [ ] Exceptions, unwinding, non-local jumps and runtime fault integration.
- [ ] Representative game/module functions and their instruction/control-flow coverage.
- [ ] Comparison of execution strategies and an explicit CPU-backend decision,
  including a Rosetta-independent compatibility path for uncovered valid targets.

The next CPU increment is stack/direct-call validation, then code-address
resolution and callbacks. Extending this whitelist is useful for isolated
correctness experiments; it is not a decision to build a complete x86 decoder or
instruction-semantics library by hand. The existing native GPU process and shared
protocol remain separate from this CPU translation work.
