# ARM64 CPU backend: P0 baseline and architecture inventory

Issue: [#9](https://github.com/bmy/bbport-mac/issues/9).
Audit date: 2026-10-22. P0 is **in progress**; game benchmarks have not been run.

## Findings and scope

The current CPU loader executes x86 game instructions directly. The existing
native renderer is reusable, but changing compiler architecture cannot translate
the game or its PS4 modules. The old CPU analysis describes a Linux AOT prototype
whose source directory is absent from the available checkout/history. A lookup of
`recompiler/run.sh` in the upstream default branch also returned 404; that does
not rule out sources on another branch or in an external archive.

The new [`recompiler/`](../recompiler/README.md) is an independent, synthetic leaf
experiment. It demonstrates x86 bytes → LLVM IR → native ARM64 execution on the
physical Mac, with differential checks. It does not reproduce the old function
corpus or establish game compatibility.

## Architecture dependencies

| Area | Existing dependency / evidence | Work needed after P0 |
| --- | --- | --- |
| CPU loader | `src/probe.c`: x86 compile guard, CPUID/XGETBV, entry assembly, executable import trampolines, direct guest entry | Introduce an execution backend and explicit guest CPU state; enter translated code through it |
| Guest ABI and callbacks | `src/runtime.h`: `sysv_abi`, guest callback and thread entry function pointers; `src/runtime.c` callback lifecycle | Define guest-to-host and host-to-guest bridges, argument/return marshaling and address resolution; audit layouts, variadic calls and return conventions |
| TLS and threads | `src/runtime_thread.c`: GS assembly, guest TCB in pthread TSD, instruction rewriting | Model guest TLS independently from host registers; enter each guest thread through the backend |
| Faults and registers | `src/platform.h`, `src/probe.c`, `src/runtime_kernel.c`: x86 `ucontext`, RIP/RBP/register assumptions | Separate host fault state from guest state and map ARM PCs back to x86 guest locations |
| Timing and CPU services | `src/runtime_kernel.c`: `x86intrin.h`, RDTSC and calibration | Preserve guest-visible timing semantics using a native host implementation |
| Unwinding / non-local exits | `src/runtime.h`, `src/probe.c`, linked guest libc and the historical CPU analysis | Inventory guest and host unwinding separately; specify exceptions, landing pads and setjmp/longjmp contracts before executing affected paths |
| Input format and linked modules | `scripts/prepare.py`, `scripts/link_modules.py`, `scripts/link_libc.py`: x86 ELF parsing, relocations, PS4 module code and FS→GS rewriting | Retain parsing of the **x86 guest input**, but route execution through translation; cover `libc.prx` and `libSceFios2.prx` |
| Patches and hooks | `scripts/patches.py`, `src/probe.c`, `gpu/shim/bbport_frame_rate.cpp`: patches to x86 code and x86 hook stubs | Apply supported patches before translation; include patches in cache identity; translate or replace hook bridges |
| Guest memory and GPU tracking | `src/runtime_memory.c`, `src/low_heap.c`, `gpu/shim/remote/`: fixed guest addresses, page protections, shared mappings and fault notifications | Preserve guest layouts; validate native page granularity, atomics, memory ordering and code-cache invalidation |
| Native renderer | `tools/macos/build_gpu_native.sh`, `gpu/shim/remote/remote_front.cpp`, `docs/macos-native-gpu.md` | Reuse the separate ARM64 process/protocol; prove CPU/backend synchronization without relying on x86 ordering |
| Build and dependencies | `tools/macos/build.sh`: explicit x86 compiler/CMake targets and `deps-x86_64`; `setup_deps.sh` checks Rosetta even for ARM64 dependencies | Separate host/guest architecture; build the CPU runtime and all loaded dependencies for ARM64; remove Rosetta checks only when no longer required |
| Launch and packaging | `tools/macos/run.sh`, `tools/macos/package.sh`, `launcher-macos/Sources/BBLauncher/Checks.swift`, `.github/workflows/release.yml` | Audit helpers, dynamic libraries, launcher checks and release jobs; prohibit an implicit Rosetta fallback in the finished ARM64 mode |

This is a source audit, not proof that all dependencies have been found. The
existing GPU shader recompiler is distinct from a CPU translator. The ARM64 SRT
walker work should be reused rather than treating the old CPU document's GPU
portability findings as the current implementation status.

## Collect a baseline manifest

```sh
python3 tools/macos/cpu_baseline.py
# When the game and native GPU build are available:
python3 tools/macos/cpu_baseline.py --game '/path/to/CUSA03173' --require-ready
```

The collector does not install anything, launch the game or modify saves/settings.
It creates a fresh manifest under `out/cpu-baseline/` containing Git/submodule
state, host/toolchain/power details, binary and dependency architectures, dynamic
link references, SHA-256 hashes, config, BB environment overrides, patch/mod
identities and optional game/module hashes. Paths and configuration are local
diagnostics; review before sharing. Existing report paths are not overwritten.

`--require-ready` exits 2 if static prerequisites are absent. Presence and
architecture checks do not validate game version, successful launch or the
architectures of the processes actually loaded. Hashes identify this build's
artifacts; the manifest does not claim existing binaries match the current source.

Local audit results:

- Apple Silicon, macOS 27.0.1; Apple clang 21.0.0; Rosetta reference execution works.
- `out/bb-probe`, `out/bb-gpu-capabilities` and `out/gpu/libbbgpu.dylib` are x86-64.
- `out/gpu-arm64/bb-gpu`, its GPU library and `deps-arm64/` are absent.
- The game is not currently available on this Mac (confirmed by the user).
- No startup, frame-time, memory or gameplay stability results have been measured.

## Prepare CPU Rosetta + native GPU measurements

Build the native GPU prerequisites when ready (these commands download and build
dependencies and are separate from the read-only manifest collection):

```sh
BB_ARCH=arm64 bash tools/macos/setup_deps.sh
bash tools/macos/build_gpu_native.sh
```

Keep a dedicated test save backup. For every run record the save identity, exact
scene/camera/route, game and module hashes, config, patches/mods, power mode and
cache state. Use the same Mac connected to power with Low Power Mode disabled;
allow thermals to settle. Keep the initial configuration fixed at 2560×1440,
FSR 3.1 Native AA, 60 FPS and model detail Highest. Archive the actual config used;
these are test settings, not performance claims.

Example launch from the checkout after configuring those settings:

```sh
mkdir -p out/cpu-baseline/reference-01
BB_NATIVE_GPU=1 BB_FPS=60 BB_UPSCALER=fsr3 \
  python3 tools/macos/cpu_baseline.py --game '/path/to/CUSA03173' \
  --output out/cpu-baseline/reference-01/manifest.json --require-ready
BB_GAME_DIR='/path/to/CUSA03173' BB_NATIVE_GPU=1 BB_FPS=60 BB_UPSCALER=fsr3 \
  BB_FRAME_STATS=1 BB_FRAME_LOG="$PWD/out/cpu-baseline/reference-01/frames.csv" \
  bash tools/macos/run.sh
cp out/last-run.log out/cpu-baseline/reference-01/run.log
```

Use the same environment overrides for collection and execution; record any
additional overrides in both commands. Confirm in logs and Activity Monitor that
`bb-probe` is Intel and the separate `bb-gpu` is Apple. Missing native GPU artifacts
must not be accepted as a measurement of this pairing.

Measurement protocol:

1. Record launch-to-title and load-save-to-controllable-character times separately.
   Record first-use shader compilation separately from warmed-cache launches; do
   not delete existing user caches merely to collect a cold result.
2. Choose an exact save and fixed camera on the Great Bridge, then a busy Central
   Yharnam scene and a fixed streaming route. Record location and route precisely
   rather than relying on the area name alone.
3. After the scene settles, record the CSV time marking the beginning of a
   60-second observation interval. Repeat each scenario three times, preserving
   each full CSV/log. Exclude menus/loading using the recorded interval, not a
   guessed GPU-time filter. Record median/p95/p99 frame time, flip rate and stutters
   above 40 ms for that interval. `frame_ms` is flip spacing, not pure CPU time.
4. Capture CPU-by-thread diagnostics where available and RSS for **both** processes.
   Existing `Memory:` log lines describe the process emitting them, not total
   memory for the pair; do not add overlapping shared mappings and call that
   unique physical memory usage.
5. Log crashes, hangs, visual errors, save/load outcome and run duration. Preserve
   raw observations even for failed runs. CPU microbenchmark timings from the AOT
   smoke test are not game performance measurements.

Avoid the existing `tools/bench.sh` for this Mac baseline: its restart/input/stop
automation follows the Linux tooling. Existing remote-channel/table/memory tests
can provide additional renderer evidence, but cannot replace gameplay validation.

## P0 completion checklist

- [x] Initial source inventory with specific architecture dependencies.
- [x] A small reproducible AOT experiment, independent from the missing historical one.
- [x] Differential execution of that experiment on physical Apple Silicon.
- [x] Baseline manifest collector and a repeatable measurement protocol.
- [ ] Inventory and hash the actual supported game and required PS4 modules.
- [ ] Recover/recreate translation of selected **game functions**, beyond synthetic leaves.
- [ ] Build and verify the CPU Rosetta + native GPU reference configuration.
- [ ] Record startup, frame-time, memory and stability measurements for fixed scenes.

P0 remains open until the missing game-dependent evidence is collected. Backend
selection and coverage claims belong to P1; this experiment does not decide them.
