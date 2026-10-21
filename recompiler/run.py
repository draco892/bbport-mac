#!/usr/bin/env python3
"""Compare original synthetic x86 bytes with LLVM AOT on x86-64 and Apple ARM64."""
import argparse
import hashlib
import json
import platform
import random
import subprocess
from pathlib import Path

from lift import lift

ROOT = Path(__file__).resolve().parent


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT.parent / "out/recompiler-p0")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = out / "verification.json"
    report.write_text(json.dumps({"status": "incomplete"}) + "\n")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("run with a native ARM64 Python on Apple Silicon")
    fixtures = json.loads((ROOT / "fixtures.json").read_text())
    codes = {name: bytes.fromhex(code) for name, code in fixtures.items()}
    ir = "\n\n".join(lift(code, name) for name, code in codes.items())
    (out / "leaves.ll").write_text(ir + "\n")
    asm = [".text"]
    for name, code in codes.items():
        asm.extend([f".globl _{name}", f"_{name}:",
                    ".byte " + ",".join(str(byte) for byte in code)])
    (out / "original.s").write_text("\n".join(asm) + "\n")
    declarations = "\n".join(f"extern uint64_t {name}(uint64_t, uint64_t);" for name in codes)
    harness = '''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
DECLARATIONS
int main(void) {
    uint64_t a, b;
    uint64_t (*functions[])(uint64_t, uint64_t) = {FUNCTIONS};
    while (scanf("%" SCNx64 " %" SCNx64, &a, &b) == 2) {
        for (unsigned i = 0; i < sizeof(functions)/sizeof(functions[0]); ++i)
            printf("%016" PRIx64 "\\n", functions[i](a, b));
    }
    return ferror(stdin) || ferror(stdout);
}
'''.replace("DECLARATIONS", declarations).replace("FUNCTIONS", ",".join(codes))
    (out / "harness.c").write_text(harness)
    edge = [0, 1, 2, 31, 32, 63, 64, 255, 0x7fffffff, 0x80000000,
            0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
    pairs = [(a, b) for a in edge for b in edge]
    rng = random.Random(0xbb109)
    pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(4096))
    inputs = "".join(f"{a:016x} {b:016x}\n" for a, b in pairs)
    (out / "inputs.txt").write_text(inputs)
    commands = []
    outputs = {}
    for label, arch, source in [("original-x86_64", "x86_64", "original.s"),
                                ("aot-x86_64", "x86_64", "leaves.ll"),
                                ("aot-arm64", "arm64", "leaves.ll")]:
        exe = out / label
        command = ["xcrun", "clang", "-arch", arch, "-O2", str(out / "harness.c"),
                   str(out / source), "-o", str(exe)]
        commands.append(command)
        build = run(command)
        (out / f"{label}.build.log").write_text(build.stdout + build.stderr)
        outputs[label] = run(["/usr/bin/arch", f"-{arch}", str(exe)], input=inputs).stdout
        (out / f"{label}.results.txt").write_text(outputs[label])
    reference = outputs["original-x86_64"].splitlines()
    comparisons = len(pairs) * len(codes)
    if len(reference) != comparisons:
        raise RuntimeError("oracle output is incomplete")
    for label, output in outputs.items():
        rows = output.splitlines()
        if rows != reference:
            first = next((i for i, (a, b) in enumerate(zip(reference, rows)) if a != b),
                         min(len(reference), len(rows)))
            report.write_text(json.dumps({"status": "failed", "backend": label,
                                          "first_mismatch_row": first}, indent=2) + "\n")
            raise RuntimeError(f"{label}: mismatch at row {first}")
    summary = {
        "status": "passed", "scope": "synthetic leaf RAX only; not game execution",
        "host": platform.platform(), "machine": platform.machine(),
        "compiler": run(["xcrun", "clang", "--version"]).stdout,
        "seed": "0xbb109", "fixtures": len(codes), "input_pairs": len(pairs),
        "comparisons_per_aot_backend": comparisons, "mismatches": 0,
        "oracle": "original x86 bytes under Rosetta; development verification only",
        "commands": commands,
        "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (ROOT / "lift.py", ROOT / "fixtures.json", ROOT / "run.py")},
        "inputs_sha256": hashlib.sha256(inputs.encode()).hexdigest(),
    }
    report.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {comparisons} comparisons per AOT backend, 0 mismatches; {report}")


if __name__ == "__main__":
    main()
