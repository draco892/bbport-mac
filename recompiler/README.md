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

## Bounded stacks and direct calls (early P1 validation)

```sh
python3 recompiler/run_stack.py
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
```

This separate experiment adds an explicit CPU state (RAX, RSI, RBX, RBP and a stack
offset), a 512-byte translated stack and direct calls among known synthetic
functions. It reuses the memory decoder's instruction subset through a decoder
extension, without changing the earlier memory/branch contract.

The whitelist supports 64-bit PUSH/POP, aligned positive imm8 SUB/ADD RSP,
MOV RBP,RSP, RSP/RBP-relative 64-bit local slots, LEAVE and direct rel32 CALL/RET.
Each function must restore its stack depth and RBX/RBP on every return. Local
frames are bounded to 128 bytes, calls require 16-byte pre-call alignment and an
acyclic call graph is checked against the total stack capacity. Reads from
uninitialized or deallocated slots and accesses to protected return-address slots
are rejected. Frame-pointer values cannot escape into scalar outputs or memory.

The x86 reference executes original CALL/RET instructions on the real host stack.
An assembly bridge seeds RBX/RBP and records RAX, RSI, RBX, RBP and the actual RSP
delta after return. AOT functions receive explicit guest state and use native,
non-inlined LLVM calls. CALL writes a synthetic return token to the translated
stack; RET checks it and restores the stack offset. Runtime guards also check
stack bounds/alignment and callee-saved register restoration.

The harness compares **25,636 register/memory/stack-balance snapshots per AOT
backend**, covering 17 functions and 1,508 input pairs, with zero mismatches on
physical Apple Silicon. Cases include nested and repeated calls, forward and
backward rel32 destinations, saved scalar values across calls, frame-pointer
prologues/epilogues and stack allocation reuse. Both memory guard regions are
checked for all runs; translated stack guards are checked for AOT runs. The
original host stack is checked through its RSP delta and ABI register snapshot.

Artifacts under `out/recompiler-stack/` include the resolved original module
bytes/offsets, assembly bridge, generated IR, harness, exact inputs, result files,
build logs and verification report. The report records analyzed stack requirements
and source hashes. `stack_fixtures.json` supplies exact function boundaries and
CALL targets; the fixture assembler only resolves these explicit CALL tokens.

This remains a synthetic straight-line experiment. It does not combine arbitrary
conditional CFGs with calls, resolve indirect targets or callbacks, or support
recursion, red-zone accesses, escaped stack addresses, stack arguments, exceptions
or a full ABI. Translated RSP is an offset, not the game's virtual stack address;
return tokens are synthetic code offsets. Dead stack bytes, native return
addresses and transient frame-pointer values are **not** compared across
architectures. No game code is executed and no full backend has been selected.

## Guest code registry and indirect calls (early P1 validation)

```sh
python3 recompiler/run_indirect.py
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
```

This experiment reuses the explicit stack/state model and adds CALL through RAX,
RBX and bounded guest memory operands. `indirect_fixtures.json` declares possible
callees for each indirect site. The combined direct/indirect call graph is checked
for cycles and worst-case stack requirements before emitting code. The original
stack-only mode still rejects indirect instructions.

The x86 reference maps a synthetic immutable code image at guest address
`0x200000000` (above 4 GiB), then executes the original bytes with real indirect
CALLs. Mapping uses a hint and verifies the returned address; it never overwrites
an occupied mapping. AOT does not execute or map those bytes. Code pointers kept
in guest registers, spills, returned values and guest memory remain those same
64-bit guest addresses. `resolve_guest_code` maps exact registered entries to
separate native LLVM functions; guest integers are never cast into callable native
pointers in the translated code. All registered entries are checked to resolve
to distinct native addresses, and interior/null addresses must not resolve.

After lookup, the caller checks the per-site allowed target set. An unregistered
address returns status 1; a registered entry outside that set returns status 2.
The faulting guest value is recorded and the error propagates through native
callers, restoring their modeled SP/RBX/RBP. RAX/RSI are unspecified on failure.
This cleanup does not roll back guest writes or implement exceptions/unwinding.
Unexpected stack/state invariant violations still use the internal trap guards.

Validation covers **16 functions, 11 indirect sites, 740 scalar input pairs and
all 9 ordered pairs of three callee choices**: 106,560 register/memory snapshots
per AOT backend, with zero mismatches on Apple Silicon. It includes pointers
spilled to the stack, pointers copied through guest memory and returned as data,
two indirect calls, nested direct/indirect calls, RBP frames, `[rdi]` calls and the
last valid 8-byte pointer slot in the 64-byte region.

Each AOT backend also passes 10 negative invocations: null, unregistered,
interior, registered-but-disallowed and actual native-function-pointer values,
through both a root indirect caller and a nested call chain. Those roots have no
guest writes before failure; tests verify unchanged memory, stack balance and
callee-saved registers. Invalid native/x86 destinations are not executed by the
reference. They are tested against the explicit AOT error contract instead.

Artifacts under `out/recompiler-indirect/` include original image bytes, the
guest-address registry, target-set manifest, LLVM IR, harness and bridge, inputs,
result files, rejection logs and source-hashed `verification.json`. The previous
stack/direct-call corpus still passes 25,636 comparisons per AOT backend.

The registry is immutable and synthetic: no automatic target discovery, arbitrary
interior entry points, module loading/unloading, code-cache invalidation or
Rosetta-independent fallback has been implemented. Indirect jumps, host/guest
recursion and game execution remain out of scope for this corpus. An address absent
from the registry is rejected even if it could be a valid target in a larger
program. This increment does not complete P1 or select the production backend.

## Synchronous host/guest callbacks (early P1 validation)

```sh
python3 recompiler/run_callback.py
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
```

This experiment adds a real native C host service and synchronous guest callback
entry through the immutable guest-address registry. Eight synthetic guest
functions include six callback entries. Original x86 code reaches C through an
import thunk and assembly ABI bridge; AOT code calls the same C service directly.
The service can reenter a registered guest callback with independent CPU state
and a fresh guarded 512-byte AOT stack, sharing the guest memory region.

Context-scoped handles support registration and revocation without reusing old
handle values. Thread-local active context is restored across nested calls;
callback depth is explicitly bounded. The host import is excluded from the guest
registry, and the original guest call graph still must be acyclic.

Validation on Apple Silicon compares **53,280 snapshots per AOT backend**, with
zero mismatches: 740 scalar pairs, six outer callbacks, three inner callbacks,
two service policies and two invocations on the same bindings/context/memory.
Snapshots cover register state, stack balance, memory guards, transition-trace
hashes, callback/service counts and peak depth. Independent count assertions
ensure nested transitions actually execute. Each AOT backend passes 10 additional
rejection/recovery checks covering invalid targets, revoked/stale handles, slot
reuse, bounded reentry failure and a successful call after handling the error.
The CPU static rejection suite now contains 32 passing tests.

Artifacts and source-hashed `verification.json` are under
`out/recompiler-callback/`. See `docs/CPU_BACKEND_P1.md` for the precise contract
and error statuses. The experiment covers synchronous same-thread scalar calls;
general host ABIs, asynchronous/cross-thread callbacks, module unloading,
exceptions and game execution remain open. It does not complete P1 or select the
production backend. SIMD/floating-point correctness is the next planned increment.
