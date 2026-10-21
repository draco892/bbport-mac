#!/usr/bin/env python3
"""Collect P0 prerequisites and file identities; does not launch or benchmark the game."""
import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def command(*argv):
    try:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
        return {"exit_code": result.returncode, "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"exit_code": None, "error": str(error)}


def file_info(path, binary=False):
    result = {"path": str(path), "exists": path.is_file()}
    if not result["exists"]:
        return result
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    result.update(size=path.stat().st_size, sha256=digest.hexdigest())
    if binary:
        result["architectures"] = command("lipo", "-archs", str(path))
        result["linked_libraries"] = command("otool", "-L", str(path))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game", type=Path, help="merged 1.09 folder containing eboot.bin")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true",
                        help="exit 2 if static baseline prerequisites are missing")
    args = parser.parse_args()
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    output = args.output or ROOT / "out/cpu-baseline" / timestamp.strftime("%Y%m%dT%H%M%S%fZ") / "manifest.json"
    if output.exists():
        parser.error(f"output already exists: {output}")
    deps_x86 = Path(os.environ.get("BB_DEPS", str(ROOT / "deps-x86_64"))).resolve()
    deps_arm = Path(os.environ.get("BB_GPU_DEPS", str(ROOT / "deps-arm64"))).resolve()
    cpu = Path(os.environ.get("BB_PROBE", str(ROOT / "out/bb-probe"))).resolve()
    gpu = Path(os.environ.get("BB_GPU_PROCESS", str(ROOT / "out/gpu-arm64/bb-gpu"))).resolve()
    targets = {
        "cpu": (cpu, "x86_64"),
        "frontend_gpu_library": (cpu.parent / "gpu/libbbgpu.dylib", "x86_64"),
        "capabilities": (cpu.parent / "bb-gpu-capabilities", "x86_64"),
        "gpu": (gpu, "arm64"),
        "gpu_library": (gpu.parent / "libbbgpu.dylib", "arm64"),
    }
    artifacts = {name: file_info(path, binary=True) for name, (path, _) in targets.items()}
    missing = []
    for name, (_, arch) in targets.items():
        item = artifacts[name]
        if arch not in item.get("architectures", {}).get("stdout", "").split():
            missing.append(f"{name}: missing or not {arch}")
    dependencies = {}
    for label, prefix in [("x86_64", deps_x86), ("arm64", deps_arm)]:
        libraries = sorted((prefix / "lib").rglob("*.dylib")) if (prefix / "lib").exists() else []
        dependencies[label] = [file_info(path, binary=True) for path in libraries if not path.is_symlink()]
        for library in dependencies[label]:
            if label not in library.get("architectures", {}).get("stdout", "").split():
                missing.append(f"deps-{label}: incompatible library {library['path']}")
        for relative in ("env.sh", "lib/kosmickrisp/kosmickrisp_mesa_icd.json"):
            if not (prefix / relative).is_file():
                missing.append(f"deps-{label}: missing {relative}")
        driver = prefix / "lib/kosmickrisp/libvulkan_kosmickrisp.dylib"
        if not driver.is_file() or label not in command("lipo", "-archs", str(driver)).get("stdout", "").split():
            missing.append(f"deps-{label}: missing or incompatible KosmicKrisp driver")
    game = {}
    if args.game:
        folder = args.game.expanduser().resolve()
        for name in ("eboot.bin", "sce_module/libc.prx", "sce_module/libSceFios2.prx", "sce_sys/param.sfo"):
            game[name] = file_info(folder / name)
            if not game[name]["exists"]:
                missing.append(f"game: missing {name}")
    else:
        missing.append("game: --game not supplied")
    rosetta = command("/usr/bin/arch", "-x86_64", "/usr/bin/true")
    if rosetta["exit_code"] != 0:
        missing.append("Rosetta unavailable for the reference CPU run")
    config = Path(os.environ.get("BB_CONFIG", str(ROOT / "bbport.ini"))).resolve()
    report = {
        "schema_version": 1, "collected_at_utc": timestamp.isoformat(),
        "measurement_status": "not_run",
        "static_prerequisites_present": not missing, "missing_prerequisites": missing,
        "note": "Presence/architecture checks only; does not validate launch, game version or loaded process architectures.",
        "git": {"head": command("git", "rev-parse", "HEAD"),
                "status": command("git", "status", "--short"),
                "submodules": command("git", "submodule", "status", "--recursive")},
        "host": {"platform": platform.platform(), "machine": platform.machine(),
                 "macos": command("sw_vers"), "hardware": command("sysctl", "hw.model", "hw.memsize", "hw.ncpu"),
                 "power": command("pmset", "-g", "custom"),
                 "compiler": command("xcrun", "clang", "--version"), "python": platform.python_version(),
                 "rosetta_reference_check": rosetta},
        "artifacts": artifacts, "dependencies": dependencies, "game": game,
        "config": {"identity": file_info(config), "content": config.read_text() if config.is_file() else None},
        "environment": {key: value for key, value in sorted(os.environ.items())
                        if key.startswith("BB_") or key in ("VK_DRIVER_FILES", "DYLD_LIBRARY_PATH")},
        "patches_and_mods": {name: file_info(ROOT / name) for name in ("patches.json", "mods.json")},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output.resolve())
    print("Static prerequisites present" if not missing else "Missing prerequisites:\n- " + "\n- ".join(missing))
    return 2 if args.require_ready and missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
