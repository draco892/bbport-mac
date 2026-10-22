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
- [x] Bounded synthetic stacks and direct calls/returns across known functions.
- [ ] General guest stack addressing, stack arguments and non-linear CFGs with calls.
- [x] Synthetic guest code-address registry and bounded indirect calls.
- [ ] General target discovery/resolution, indirect jumps and host/guest callbacks.
- [ ] Full observable guest register/flag state, beyond the current contracts.
- [ ] SIMD and floating-point semantics, rounding, NaNs and exceptional inputs.
- [ ] Atomics and an explicit strategy for x86 memory ordering on ARM64.
- [ ] Exceptions, unwinding, non-local jumps and runtime fault integration.
- [ ] Representative game/module functions and their instruction/control-flow coverage.
- [ ] Comparison of execution strategies and an explicit CPU-backend decision,
  including a Rosetta-independent compatibility path for uncovered valid targets.

The next CPU increment is host/guest callback validation using the explicit
guest-address registry. Extending this whitelist is useful for isolated
correctness experiments; it is not a decision to build a complete x86 decoder or
instruction-semantics library by hand. The existing native GPU process and shared
protocol remain separate from this CPU translation work.

## Completed increment: bounded stacks and direct calls

```sh
python3 recompiler/run_stack.py
```

`stack_lift.py` extends the shared decoder with stack instructions and direct
rel32 calls, then validates the complete synthetic module before IR emission.
Every target must be an exact known function entry; overlapping functions,
unknown/mid-function targets and cyclic call graphs are rejected. Function
boundaries and code offsets come from `stack_fixtures.json`, not code discovery.

The abstract stack tracks initialized values and the identity of saved RBX/RBP.
PUSH/POP and local loads/stores propagate those identities. Deallocation discards
slot initialization; LEAVE must refer to a valid local frame. A RET requires a
defined result, zero local stack delta and restored RBX/RBP. Direct calls are
allowed only with aligned stacks, and the whole call graph's stack requirement is
checked against the 512-byte region (including space for the root return token).
Local frames are limited to 128 bytes. The fixtures' maximum analyzed requirement
is 128 bytes below a function's entry SP.

The generated LLVM IR represents RAX, RSI, RBX, RBP and SP explicitly. Callees are
native `noinline` functions receiving shared CPU state, memory and stack pointers.
Each call pushes a synthetic return token, and each return checks that token,
stack balance and callee-saved register values. Additional guards check entry
stack bounds/alignment. RBP-relative local addresses are validated symbolically;
their temporary pointer values are not exposed by the supported contract.

The original x86 module uses real CALL/RET instructions and the host stack. A
small assembly bridge preserves the host's own callee-saved registers, seeds the
fixture RBX/RBP values, invokes each original entry and captures the final guest
registers plus actual RSP delta. The C harness compares those observations with
the translated state and checks guest-memory guards. AOT runs additionally check
guards surrounding their explicit stack region.

| Evidence | Result |
| --- | --- |
| Synthetic functions, each also tested as a root entry | 17 |
| Boundary + seeded random input pairs | 484 + 1,024 |
| Original x86 vs explicit-state AOT x86-64 | 25,636 snapshots; zero differences |
| Original x86 vs explicit-state AOT ARM64 | 25,636 snapshots; zero differences |
| Observed state | RAX, RSI, RBX, RBP, normalized RSP delta and the memory/guard snapshot |
| Original RSP/RBX/RBP restoration and AOT stack guards | Passed |
| Stack/call rejection tests and previous memory/branch regression suite | Passed |

Coverage includes nested calls with frame pointers, callee-saved register
preservation, local spills across a call that changes RSI/RAX, allocation reuse
and both positive and negative call displacements. The earlier memory/forward-
branch experiment still passes its 70,876 comparisons per AOT backend.

This does not compare dead stack contents, real code/stack pointer values or raw
return addresses across architectures. AOT SP is an offset into a test buffer and
return tokens are synthetic module offsets. Accesses to return-address slots,
uninitialized slots and escaping frame pointers are rejected. Recursion, indirect
calls, stack arguments, exceptions, full guest virtual addresses and combined
conditional stack/call CFGs remain unsupported. The stack experiment is separate
from the previous conditional-branch corpus; neither demonstrates a whole game
runtime or completes P1.

## Completed increment: guest code addresses and bounded indirect calls

```sh
python3 recompiler/run_indirect.py
```

The indirect mode extends `stack_lift.py` with an immutable registry mapping
synthetic guest entry addresses to native function pointers. The code base is
`0x200000000`, exercising pointer values above 32 bits. The translated CPU state
adds a resolution-error code and faulting address to the existing five fields.
Known entries resolve to LLVM functions; guest values are never used directly as
native call pointers. Every call additionally checks the target set declared for
that specific instruction in the fixture manifest.

Function boundaries and target sets are supplied explicitly. The analyzer includes
every possible declared indirect edge in cycle detection and worst-case stack
accounting. Missing, duplicate, unknown or unused target declarations are rejected,
as are uninitialized register targets, misaligned calls and memory operands outside
the bounded region. Runtime lookup rejects non-entry addresses; a separate check
rejects a registered function that is not allowed at the current call site.

For the original x86 reference, the harness maps the same module bytes at their
guest code addresses with read/execute protection after copying. It requests a
free mapping with an address hint and fails explicitly if the exact address is
unavailable. It does not replace an existing mapping. Real x86 indirect CALLs
therefore consume exactly the 64-bit guest pointers stored in the fixture memory.
The AOT process resolves these integers without mapping or executing the original
image. Guest code pointers can survive stack spills, memory round trips and
returns as data without being replaced by native pointer values.

| Evidence | Result |
| --- | --- |
| Functions / indirect call sites | 16 / 11 |
| Scalar inputs | 484 boundary pairs + 256 seeded random pairs |
| Callee choices | All 9 ordered pairs from 3 different functions |
| Original x86 vs explicit-state AOT x86-64 | 106,560 snapshots; zero differences |
| Original x86 vs explicit-state AOT ARM64 | 106,560 snapshots; zero differences |
| Controlled invalid-target invocations | 10 passed per AOT backend |
| Original stack/direct-call regression | 25,636 comparisons per AOT backend passed |
| Static rejection tests, including prior CPU contracts | Passed |

The valid corpus covers CALL through RAX/RBX, `[rdi]` and `[rdi+disp8]`, including
the last valid pointer slot; spilled/persisted pointers; changing the callee
between invocations; frames, nested calls and two indirect calls in sequence.
Resolver checks also verify all known entries, reject their interior addresses
and confirm native callable pointers differ from their guest identities.

Resolution failures have an explicit contract: status 1 means unregistered guest
address, status 2 means registered but not allowed at this site. The faulting value
is recorded; errors propagate through callers with SP/RBX/RBP restored. RAX/RSI
are unspecified after failure. This is bounded error cleanup, not exception
handling or transactional memory rollback. Negative cases cover null, unknown,
interior, disallowed and actual native-pointer inputs, both at a root site and
through a direct-call chain. These particular roots perform no guest writes before
failure, so their negative tests require unchanged memory. They do not execute
invalid targets in the x86 reference. Stack invariant corruption still traps.

This is an immutable synthetic registry, not a recovered game CFG, real PRX loader
or complete target resolver. Valid targets outside the declared registry are
rejected; a compatibility fallback still needs design and validation. Indirect
jumps, host/guest callbacks, dynamic code changes, general guest stack addresses
and combined conditional call CFGs remain unsupported. P0's missing game evidence
and P1's remaining correctness/architecture gates remain open.
