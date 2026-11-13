# Checked guest memory in the common CPU state

Updated 2026-11-13. Part of [issue #9](https://github.com/bmy/bbport-mac/issues/9).
The memory-access portion now has a common-state implementation, including
dynamic guest-address translation, byte/word/dword/qword accesses and scalar
GPR/flag instruction sequences. The previous `memory_lift.py` mode remains as
the restricted forward-control-flow reference and decoder dependency for the
older stack/callback experiments. Migrating that control flow stays separate.

## CPU and mapping contracts

Translated functions take `BbCpuState *` and a trusted host `BbGuestMemory *`.
The CPU state retains its existing 416-byte ABI. The new mapping descriptor is
48 bytes, with actual C offsets checked at compile time on both architectures:

| Field | Byte offset | Meaning |
| --- | --- | --- |
| bytes | 0 | Trusted host buffer pointer |
| guest_base | 8 | Guest address of the buffer's first byte |
| byte_size | 16 | Accessible extent, from 0 through 64 bytes |
| permissions | 24 | Read=1, write=2; 0 denies both |
| fault_address | 32 | Rejected effective guest address |
| fault_offset | 40 | Failing instruction's byte offset within the fixture |

Buffers, mapping descriptor and CPU state must be disjoint. The caller supplies
a real host allocation covering byte_size; that host-allocation validity is a
trusted API precondition. Registers and guest addresses are 64-bit integers.
LLVM forms the host pointer from the descriptor buffer plus a checked offset,
only after both bounds and permission checks. No guest integer is cast to a
native pointer; no `inbounds`, `nsw` or `nuw` assumptions are used.

The descriptor is validated before any fixture instruction executes. Size must
be at most 64, guest_base+byte_size must fit in 64 bits, permission bits must be
known, and a nonempty buffer must be nonnull. Empty buffers may be null.
Metadata is reset to zero on entry. The CPU status codes are:

| Status | Meaning | Effects |
| --- | --- | --- |
| 0 | Success | All instructions committed; fault metadata stays zero |
| 1 | Access outside the region | Failed instruction has no CPU/memory effect |
| 2 | Invalid mapping descriptor | No fixture instruction executes |
| 3 | Permission denied | Failed instruction has no CPU/memory effect |

On status 1 or 3 the exact rejected effective address and instruction offset
are retained. Bounds take priority over permission errors. Earlier successful
instructions remain committed: a valid store followed by a rejected load keeps
the store and preserves the failed load's destination. This is precise checked
failure behavior, not rollback of the whole fixture or an atomicity guarantee.
RIP remains unchanged under the synthetic leaf contract; fault_offset is not
runtime dispatch, unwinding or guest exception delivery.

## Supported instructions and addressing

- MOV loads/stores of 8, 16, 32 and 64 bits, with unaligned `align 1` accesses.
- MOVZX and MOVSX from memory bytes/words into 32- or 64-bit GPRs, plus MOVSXD
  from a memory dword into a 64-bit GPR.
- All 16 data/base registers. Byte operands use canonical REX selection for
  SPL/BPL/SIL/DIL and R8B–R15B; AH/CH/DH/BH remain unsupported.
- Base-register addressing, signed disp8/disp32, SIB with scales 1/2/4/8,
  extended base/index registers, no-index SIB and index-only/no-base SIB.
- Modulo-64-bit effective-address arithmetic, including scaled-index overflow
  that wraps back into the mapped region. RSP/R12 and RBP/R13 special forms and
  aliased base/destination registers have explicit fixtures.
- The existing bounded 32/64-bit GPR arithmetic/flag/CMOV subset can execute
  before, between and after memory instructions in the same common state.

Byte/word loads preserve the upper destination bits; dword loads zero the upper
32 bits. MOVSX into a 32-bit destination sign-extends within that dword and then
zero-extends to the full 64-bit register. Partial stores change only their bytes.
Loads/stores preserve RFLAGS; carry and comparisons can be consumed by scalar
instructions after an access. Effective addresses use the current registers,
including a base modified by an earlier load or scalar instruction.

Whole fixtures decode before IR emission. Unsupported code fails closed. Memory
arithmetic instructions, SIMD loads/stores, RIP-relative addressing, address-size
or segment overrides, atomics, branches, calls, stack operations and general
guest code dispatch remain outside this new mode. It currently maps one bounded
region, not a PS4 address space or multi-region page table.

## Reference and independent checks

The reference uses separate C descriptor/bounds/permission checks, then executes
the actual original x86 instruction bytes for each allowed access. Two guest
regions are mapped at 8 GiB+16 and 16 GiB+16 in the x86 process. mmap uses a hint
and verifies the returned address; MAP_FIXED is never used to replace an occupied
mapping. ARM64 accesses equivalent host buffers through the explicit descriptor.

The x86 capture wrapper is reused from the verified GPR oracle. Actual guest GPR
values, including RSP/RDI, are loaded and captured around each original instruction.
For memory MOVs, its one flag-preserving register-MOV placeholder is replaced
with the validated memory instruction's exact bytes. Reference C checks never
substitute a C load/store for an allowed guest memory instruction.

This is an instruction-by-instruction reference, not native execution of a whole
game function. Invalid accesses are handled by the checked contract instead of
triggering hardware faults. The isolated oracle retains the GPR experiment's
boundaries around arbitrary hardware RSP values, signals and unwinding. It does
not validate asynchronous exception delivery or guest CALL/RET.

Full snapshots contain 416 CPU bytes, 16 fault-metadata bytes and the 64-byte
region with two 16-byte guards: **528 bytes per invocation**. The harness also
checks CPU/descriptor guards, all XMM registers, RIP, MXCSR, non-arithmetic RFLAGS,
the reserved sentinel and descriptor input fields independently. Host MXCSR or
FPCR/FPSR is seeded nondefault; ARM FPSR.QC alternates clear/set for each fixture.

An independent Python model uses arbitrary-precision integer bounds and byte
slices. It checks every directed target case, all descriptor-edge cases on every
fixture, and selected shared inputs on every fixture. The decoder is shared with
IR/reference generation; actual x86 memory bytes and literal answers provide
additional evidence rather than a claim of independent decoder proof.

## Reproduce and measured evidence

Requires native ARM64 Python 3.11+, Xcode/Command Line Tools and Rosetta for the
development x86 reference. No game files or network downloads are needed.

```sh
python3 -m unittest discover -s tests -p 'test_cpu*lift.py' -v
python3 recompiler/run_state_memory.py --sanitize
```

The default output is `out/recompiler-state-memory/`; `--out PATH` preserves
another run and `--random-count N` controls additional seeded random inputs.

| Check | Result |
| --- | --- |
| Fixtures × inputs | 868 × 5,677 |
| Original checked x86 vs AOT x86-64 | 4,927,636 complete CPU/memory snapshots, zero differences |
| Original checked x86 vs AOT ARM64 | Same 4,927,636 snapshots, zero differences |
| Native ARM64 UBSan | Complete corpus passed without differences or sanitizer findings |
| Literal complete-snapshot answers | 26 passed per executable |
| Independent model | 274,069 complete snapshots passed, including 5,266 directed cases |
| Combined CPU static/acceptance/layout suite | 72 tests passed |

Every primitive fixture must exercise all four status codes, or the runner fails
even if the observed outputs agree. In this run there are 156,586 successes,
4,724,746 bounds rejections, 8,680 invalid-descriptor rejections and 37,624
permission rejections per executable. The large negative count includes cross-
testing each individually directed register bank against all other fixtures;
these counts are synthetic invocation counts, not game compatibility evidence.

Literal answers include sign/zero extension, byte/word upper-bit preservation,
last-valid and first-invalid qword accesses, overlapping stores, scaled-index
wrap, base/destination aliasing, CF across a load, completed effects before a
fault, descriptor rejection before scalar effects, denied access without writes,
and a valid empty/null mapping followed by a bounds failure.

`verification.json` retains commands, compiler, source/input/result hashes,
outcomes per fixture and the mapping/state contracts. All four result hashes
match. Inputs, generated C/assembly/LLVM, explicit expected snapshots and logs
remain in the output directory. Identical results are archived once, and a full
gzip round trip is verified before raw copies are removed. Failed runs retain a
failed report and raw diagnostics instead of leaving an earlier success report.

The next step is migrating stack/CALL/RET contracts onto this common state and
guest mapping; then indirect calls/callbacks and combined control flow. Real
game coverage, multiple-region mapping, faults/unwinding, memory ordering and
runtime integration remain open. The user performs actual gameplay tests.

References: [Intel effective-address and SIB encodings](https://cdrdv2-public.intel.com/843829/325383-sdm-vol-2abcd-dec-24.pdf),
[Intel MOV/MOVSX/MOVSXD instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
