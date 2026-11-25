# Stack and direct calls in the common CPU state

Updated 2026-11-25. Work for [issue #9](https://github.com/bmy/bbport-mac/issues/9).
The bounded stack/direct-call contract now uses the same 416-byte `BbCpuState`
as GPR, SIMD and checked guest memory. This migrates all 17 original direct-stack
fixtures and adds stack arguments, all-register PUSH/POP, explicit guest return
addresses and precise checked failure propagation. It does not complete P1 or
integrate the experiment into the running game.

## State, mappings and control flow

Entry functions take CPU state, a data mapping of at most 64 bytes, and a separate
stack mapping of at most 512 bytes. Both use the existing 48-byte `BbGuestMemory`
descriptor. Descriptors are checked together before any root instruction:
nonnull buffers for nonempty extents, size limits, nonwrapping guest ranges,
known permission bits, and disjoint guest data/stack ranges. Host allocations,
descriptors and CPU state remain trusted disjoint buffers.

Implicit PUSH/POP/CALL/RET accesses use the stack descriptor. Ordinary memory
operands choose data or stack by their effective guest address, so a copied stack
pointer in R8 can address stack arguments too. If neither region contains the
starting address, RSP/RBP-based operands select stack fault metadata and other
bases select data metadata. Each access must fit wholly within one descriptor.
This two-region experiment does not provide a general page table.

RSP and RBP are guest integers. Native ARM64 never installs a guest RSP as its
host stack pointer. Checked offsets are converted into host-buffer pointers only
after bounds and permissions pass. Earlier successful instructions remain
committed after a later rejection; unwinding native helper calls never repairs
or rolls back guest registers or memory.

Supported stack/control instructions:

- 64-bit PUSH/POP for all sixteen GPRs, including the original-value rule for
  PUSH RSP and the destination replacement rule for POP RSP.
- RBP frames and LEAVE, plus existing scalar and memory MOV forms.
- ADD/SUB RSP with signed imm8 or imm32. Shared scalar lowering computes all
  arithmetic flags and preserves the original ADD vs SUB operation, including
  negative immediates. The raw GPR-mode decoder remains register-only.
- Direct CALL rel32 to registered function entries and near RET.
- Existing bounded GPR/flag instructions, byte/word/dword/qword memory forms,
  unaligned frame slots and stack arguments beyond the sixth integer argument.

Code is a known immutable synthetic image at `0x600000000`. CALL writes the full
64-bit guest continuation address to the mapped stack, commits the decremented
RSP, then calls the registered translated function. Host function pointers never
appear in guest registers or stack bytes. RET checks the read target against the
expected continuation before committing RSP+8 and guest RIP. The root return
boundary is `0x600010000`. RIP tracks the active guest instruction, its next
instruction and direct-call/return targets in this mode; older leaf modes still
preserve their input RIP.

RET to another value is a controlled status-4 rejection, even when the target
could be valid x86 code. General returns, indirect branches and target discovery
remain open. Registered functions must not overlap or collide with the root
boundary. Recursive graphs, depth above 16 and more than 4,096 expanded
instructions per root are rejected before code generation. Only straight-line
function bodies are accepted; arbitrary branches and loops are not yet migrated.

No alignment fault is invented for an unaligned stack operand. The harness
includes aligned ABI frames and unaligned instruction cases. For roots marked
ABI-conforming, successful runs must restore RBX, RBP, R12–R15 and RSP apart from
the root RET's eight-byte pop. Special bare POP/LEAVE probes explicitly opt out
of that function-ABI check while retaining full instruction-state comparison.

## Checked failures

Status 1 means a region-bound failure, 2 an invalid/overlapping mapping pair,
3 missing permissions, and 4 an unexpected RET target. Fault addresses remain
guest integers. `fault_offset` now identifies the byte offset in the synthetic
code image, including failures in a callee; RIP remains at the failing instruction.

A failed PUSH/CALL write does not decrement RSP. A failed POP read does not
modify its destination. A rejected RET does not pop. The checked LEAVE contract
validates its RBP-based read before publishing either RSP or RBP. These are
explicit checked-rejection rules; hardware exception partial-state behavior,
signals, unwinding and guest exception delivery are not established by them.

A callee's failure propagates with its active RIP, current RSP, modified registers
and all earlier stack/data writes intact. In particular, the CALL's guest return
address and any caller register changes remain observable. Invalid descriptors
are rejected before executing even an initial scalar instruction. Both descriptor
fault records are reset at root entry, without modifying their input fields.

## Two x86 reference checks

The first reference performs independent C access/return-policy checks, then
executes actual original x86 scalar, memory, PUSH, POP, adjustment and LEAVE bytes.
Its checked CALL/RET operations record the registered guest continuation and
update explicit CPU state. It checks negative cases without deliberately jumping
to corrupt targets or accessing outside the supplied memory.

Every successful reference invocation is then replayed as an entire original
x86 function, with real nested CALL/RET and the complete mapped guest stack.
The executable code image, data buffer and stack buffer are mapped at their
exact guest addresses using verified mmap hints, never MAP_FIXED. The code image
is initialized writable then made read/execute before use.

The bridge enters via a jump, so it does not push a host return address into the
guest stack. The root's guest return boundary jumps to a host capture bridge
without changing registers or flags. All sixteen GPRs, defined arithmetic flags,
the complete data region and every stack byte are compared against the checked
execution. This checks retained CALL return slots without normalizing guest
addresses into host pointers or excluding unused stack bytes.

The isolated x86 oracle uses scratch XMM registers to retain its host state and
temporarily executes on mapped guest RSP values. No guest SIMD instructions are
accepted in this mode. Asynchronous signals, reentrant callbacks and fault
unwinding are outside the native development oracle contract. Translated ARM64
uses its normal native call stack independently of the guest stack.

## Reproduce and measured evidence

Requires native ARM64 Python 3.11+, Xcode/Command Line Tools and Rosetta for the
development references. No game assets or downloads are required.

```sh
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
python3 recompiler/run_state_stack.py --sanitize
```

Artifacts default to `out/recompiler-state-stack/`; `--out PATH` selects another
run, and `--random-count N` changes the seeded random additions. Binary input
records are 1,120 bytes. Each complete output snapshot is 1,088 bytes: CPU state,
two fault records, data and stack, including both pairs of sixteen-byte guards.
All stack bytes start initialized; root return/argument slots are seeded before
execution as part of the harness input protocol.

| Check | Result |
| --- | --- |
| Entries × input states | 70 × 1,929 |
| Checked original x86 vs AOT x86-64 | 135,030 complete snapshots, zero differences |
| Checked original x86 vs AOT ARM64 | Same 135,030 snapshots, zero differences |
| Native ARM64 UBSan | Full corpus passed without differences or sanitizer findings |
| Whole original x86 functions with real CALL/RET | 57,709 successful runs replayed, full CPU/data/stack agreement |
| Independent Python model | All 135,030 complete snapshots passed |
| Literal full-state answers | 40 passed per executable |
| Combined CPU acceptance/rejection/layout suite | 89 tests passed |

Each executable observes 57,709 successes, 57,918 bounds failures, 840 invalid
descriptors, 16,261 permission failures and 2,302 rejected returns. Tests cover
all-register round trips, saved registers, nested frames, immediate adjustments,
stack arguments, base aliases, unaligned slots, return-address inspection,
corrupt returns, failures after committed effects inside nested calls, carry
consumers after CALL, and undefined logical AF carried through CALL/CMOV.

The independent model uses Python byte arrays and integer arithmetic, including
signed-range/nibble checks for immediate flags. It shares the decoder and scalar
model with other experiments; the literal answers and whole original x86 replay
provide additional evidence rather than an independent decoder proof. Rosetta is
the development x86 reference, not a physical Intel measurement.

The harness checks CPU and memory guards, XMM preservation, MXCSR, non-arithmetic
RFLAGS, the sentinel, descriptor input preservation and host FP state. ARM FPCR/
FPSR is seeded nondefault with QC initially clear and set. `verification.json`
records exact inputs, source/compiler/result hashes, per-entry outcomes, expanded
work bounds and the observed whole-native replay count. Identical snapshots are
retained once in a gzip archive after verifying a full decompression round trip.
Reports start incomplete and become passed only when every check finishes.

The GPR and checked-memory regression suites were also rerun after introducing
the shared immediate lowerer and configurable memory-helper limit. Their default
contracts retain their previous comparison counts and results.

The next integration gate is indirect calls/callbacks in this state, followed by
combined control flow and SIMD memory. The existing legacy stack/indirect modes
remain regression references. General ABI coverage, recursive execution,
exceptions, atomics, real game functions and production backend integration
remain open. Launching Bloodborne still uses the Rosetta CPU reference.

References: [Intel instruction reference, including CALL and LEAVE](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf),
[Intel instruction reference, including PUSH, POP and RET](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
