# CPU Rosetta + native GPU: initial real-game reference

Status: **partial baseline**, collected on 2026-10-27 from commit `e9794d1`.
The later controlled clinic trial below adds three real-game fixed-camera
intervals, visual timing bounds, save/load evidence and orderly shutdown. The
extended Yharnam/Great Bridge/streaming comparison remains pending.
The real game initializes its linked PS4 modules and produces frames with the
CPU running under Rosetta and the GPU process running as ARM64. The user also
confirmed a visible game/menu window during a separate live retry. This
establishes the reference pairing and visible startup; it does not establish
full visual correctness, title-screen timing, playable gameplay or completion
of P0.

## Game and prerequisites

- Bloodborne CUSA03173, `APP_VER=01.09`, local `asset/CUSA03173`.
- Loaded executable image SHA-256:
  `071df19c8880086d97182dbc057bc8cb37badaca57d9112683836b24a0444c0a`.
  This matches the image supported by `scripts/game_check.py`.
- The executable and both required PS4 modules parse as x86-64 input.
  Module 0 (`libc.prx`) and module 1 (`libSceFios2.prx`) each return zero from
  initialization in the reference run.
- The full existing DCX checker reports **0 of 26,913 files** failing to unpack.
  This is decompression validation, not a comparison with a complete known-good
  content manifest. Full shader and executable checks also pass.
- Apple M5 Pro, macOS 27.0.1, AC power, power mode 0 (Low Power Mode disabled).
- The refreshed native GPU prerequisite suite passes all steps, including the
  x86/Rosetta-to-ARM64 memory test and native Vulkan 4,096-byte readback.

| Input file | File SHA-256 |
| --- | --- |
| `eboot.bin` | `d65f0b4f01d59166aed16f8604196d8b7dd805abbf0758b356e8f1354c9429f9` |
| `sce_module/libc.prx` | `4378b47f46f1d856824a6f971db1a0c3f41833b77f49d2fba9538f667a139166` |
| `sce_module/libSceFios2.prx` | `3b8eb4d5a5c5a7b381d8d0610077e6cd404c29695a686274802f6b2737f6bf22` |
| `sce_sys/param.sfo` | `e2518cb75cb9f690f94e16ce06fa3012104fae67ed7830d953ecc072c2ff8384` |

## Reference configuration and evidence

The trial uses a fresh isolated data/save/config directory, with no supplied
existing save or mods: 2560×1440 scene, FSR 3.1 Native AA (`preset=0`), 60 FPS mode,
Highest model detail (`model_lod=-2`), and the macOS default copy-based memory
model (`BB_PC_MODEL=0`). User settings and pre-existing caches were preserved.
The window reports 3024×1746 drawable pixels on the Retina display; the configured
scene/output resolution must not be confused with that window size.

macOS `sample` reports the actual running processes as:

| Process | PID | Reported code type |
| --- | --- | --- |
| `bb-probe` | 15772 | X86-64 (translated) |
| `bb-gpu` | 15823, child of 15772 | ARM64 |

The GPU sample includes the loaded GPU library, SDL, Vulkan loader and KosmicKrisp.
The game log confirms native GPU readiness, both module initializers, guest entry
and subsequent rendering/flip statistics. This is stronger evidence than binary
architecture inspection alone.

The process was observed for **146.67 seconds** from the launch command, with
**7,840 complete CSV records spanning 132.0191 seconds** from the first logged
flip. The first record has no preceding frame interval and is excluded from
frame-time percentiles. These records include startup, intro/menu activity and
shader compilation; no visually identified gameplay interval was recorded.

| Startup-only diagnostic | Observed value |
| --- | --- |
| Median / p95 / p99 flip interval, all positive intervals | 16.46 / 19.83 / 20.576 ms |
| Intervals over 40 ms / maximum | 11 / 483.11 ms |
| Diagnostic window, CSV time `[30, 90)` | 3,600 intervals; median 16.43 ms; p99 20.49 ms; none over 40 ms |
| CPU process peak sampled / last sampled RSS | 1,255.02 / 486.91 MiB |
| GPU process peak sampled / last sampled RSS | 571.59 / 571.59 MiB |

These are startup diagnostics, **not Yharnam performance measurements**. The
60-second window was selected by CSV time, with no scene identity. RSS was sampled
approximately every two seconds; these are observed peaks, not continuous peaks.
Shared mappings mean the two RSS figures must not be summed as unique physical
memory. The native port pipeline cache started fresh; the global driver cache was
preserved, so this is not a controlled fully cold driver-cache run.

No unexpected process crash was observed before the deliberate end of the trial.
`SIGTERM` did not terminate the CPU process; after about 19 seconds it was stopped
with `SIGKILL` (exit `-9`). The GPU process then exited with its parent. This is
not a successful graceful-shutdown test. Buffered CSV/log output may have lost
the final records; the summary uses only complete CSV records.

## Retained artifacts and reproduction

Local ignored artifacts are under
`out/cpu-baseline/reference-20261027T142102Z/`: `manifest.json` (static prerequisites,
file hashes and toolchain), `game-validation.json`, `dcx-check.log`, `console.log`,
`frames.csv`, `process-observations.jsonl`, both `.sample.txt` reports,
`operator-stop.json`, `run-state.json`, `summary.json`, build logs and the isolated
config/save/cache profile. Native prerequisite artifacts are under
`out/native-gpu-check/20261027T142003853124Z/`.

Both GPU architectures and the CPU loader were rebuilt from the current source.
The standard `tools/macos/build.sh` stopped because its FSR patch application did
not accept the existing modified submodule. No submodule files were reset.
The reference x86 GPU build instead used `BB_FSR_VULKAN_SOURCE_DIR` pointing at
the isolated, pinned and patched source prepared by `build_gpu_native.sh`.
The actual build logs and a repeatable `build/build-reference.sh` are retained
with the trial. This workaround does not fix the standard build script.

For the next run, create a new directory and copy this trial's `bbport.ini`; set
the following overrides consistently for both the baseline collector and launch:

```sh
# Replace this with a fresh absolute output directory.
trial="$PWD/out/cpu-baseline/reference-next"
mkdir -p "$trial"
cp out/cpu-baseline/reference-20261027T142102Z/bbport.ini "$trial/bbport.ini"
export BB_DATA_DIR="$trial" BB_CONFIG="$trial/bbport.ini"
export BB_GAME_DIR="$PWD/asset/CUSA03173" BB_NATIVE_GPU=1 BB_PC_MODEL=0
export BB_GPU_PROCESS="$PWD/out/gpu-arm64/bb-gpu" BB_GPU_DEPS="$PWD/deps-arm64"
export BB_FPS=60 BB_UPSCALER=fsr3 BB_UPSCALE_PRESET=0 BB_MODS_ENABLED=0
export BB_FRAME_STATS=1 BB_FRAME_LOG="$trial/frames.csv"
python3 tools/macos/cpu_baseline.py --game "$BB_GAME_DIR" \
  --output "$trial/manifest.json" --require-ready
bash tools/macos/run.sh
```

## Remaining baseline gates

- User feedback confirms no existing gameplay saves are available. After the
  original trial had stopped, the window was not seen; in a separate live retry
  under `out/cpu-baseline/visibility-20261027T145148Z/`, the user confirmed
  "Sì, vedo il gioco o il menu". The confirmation is recorded in that retry's
  `user-visual-confirmation.json`, preserving the original trial artifacts.
  Visible startup is confirmed; the exact screen identity, visual correctness
  and gameplay are not established by this answer.
- Identify the title screen precisely and measure launch-to-title on a timestamped
  observation. The available UI controller could not select the unbundled GPU
  executable, and the user confirmation does not provide a title timestamp.
- Create a test save through normal gameplay, or use a suitable save if one
  becomes available; back it up before copying it into the isolated profile.
  Measure load-save-to-controllable-character separately.
- Record the exact Great Bridge camera, busy Central Yharnam scene and streaming
  route; observe each for 60 seconds and repeat each three times, retaining scene
  identities and CSV interval boundaries.
- Measure warmed starts, gameplay memory and stability, save/load behavior and
  visual errors; investigate the unresponsive `SIGTERM` behavior separately.
- Translate and validate representative real game/module functions for the
  remaining CPU P0 gate. This trial only validates the Rosetta reference.

## Follow-up: controlled clinic measurements

Artifacts: `out/cpu-baseline/measured-20261027T155044Z/`, in particular
`measurements.json`, `intervals-clinic.json`, `manifest.json`, `visual-events.jsonl`,
screenshots, raw `frames.csv`, process observations, savedata backup and hashes,
`runtime-fix.diff`, source hashes and `pad-regression.log`.

The user-created save from the earlier visibility session loads successfully.
A backed-up copy was used. The character responds to movement/camera input,
and doors and room transitions were exercised in exploratory trials. An ordinary
character death and subsequent loading into Hunter's Dream were observed; this
was not a process crash. Early Dream intervals were superseded because a camera
change invalidated the fixed-scene comparison.

The investigation found that button prompts could initialize pad bindings before
`sample_host`, bypassing publication of `mouse_look=0` to the GPU window. The
runtime now publishes the setting in that initialization path too. A pad test
reproduced the missing publication before the fix and passes afterward, covering
disabled and default mouse look plus the existing pad suite. The CPU loader was
rebuilt; GPU code and graphical settings were unchanged. The final trial uses
`mouse_look=0` to prevent desktop mouse motion from rotating the camera.

The controlled scene is the initial clinic treatment room: the idle character
beside the treatment table, looking across the room toward shelving and the
lit door alcove. `clinic-fixed-scene.jpg`, `clinic-static-middle.jpg` and
`clinic-static-end.jpg` retain matching camera views. No scripted input occurred
during the three consecutive 60-second intervals, separated by five-second gaps.
The 1440p / FSR 3.1 Native AA / Highest configuration is unchanged.

| Repeat | CSV interval (seconds) | Flips/s | Median / p95 / p99 (ms) | Frames over 40 ms | Worst (ms) |
| --- | --- | --- | --- | --- | --- |
| 1 | [432, 492) | 26.55 | 34.10 / 51.118 / 52.595 | 415 | 53.80 |
| 2 | [497, 557) | 19.65 | 33.99 / 51.987 / 716.683 | 273 | 968.09 |
| 3 | [562, 622) | 21.80 | 34.415 / 51.925 / 409.256 | 417 | 982.87 |

All three intervals record zero shader/pipeline compiles. CPU-process peak sampled
RSS is 330.86–337.78 MiB across these intervals; GPU-process peak sampled RSS is
1,287.30–1,306.39 MiB. Thread CPU diagnostics and wait statistics remain in the raw
log. The performance issue is tracked in [the roadmap](ROADMAP.md).

Other desktop apps remained open; focus/foreground changes were not instrumented.
The retained outliers must not be attributed to a particular CPU/GPU bottleneck
without profiling. These are three contiguous repetitions, not three independent
reloads of the same save. The scene is an early-game reference and does not stand
in for the planned Great Bridge or busy Central Yharnam tests.

The final process was observed for 1,031.29 seconds and ended when the user closed
the application: the log records `Window: closed (quit)` and GPU exit 0; the CPU
also exited 0. No game processes remained afterward. This verifies orderly window
closure for this trial, unlike the original forced termination.
