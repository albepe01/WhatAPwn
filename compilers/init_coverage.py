#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCHMARKS = ROOT.parent / "benchmarks"


def parse_protections_flags(src_dir: Path) -> list[str]:
    """
    Reads the protections_<target>.txt file and translates it into clang/linker flags.
    """
    target = src_dir.parent.name
    prot_file = src_dir / f"protections_{target}.txt"
    if not prot_file.exists():
        return []

    flags: list[str] = []
    for raw in prot_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue

        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().upper()
            v = val.strip().upper()
        else:
            key = "UNKNOWN"
            v = line.upper()

        if key == "RELRO":
            if "FULL" in v:
                flags += ["-Wl,-z,relro", "-Wl,-z,now"]
            elif "PARTIAL" in v:
                flags += ["-Wl,-z,relro"]

        elif key == "STACK":
            if "NO CANARY" in v:
                flags += ["-fno-stack-protector"]
            else:
                flags += ["-fstack-protector-strong"]

        elif key == "NX":
            if "ENABLED" not in v:
                flags += ["-Wl,-z,execstack"]

        elif key == "PIE":
            if "NO PIE" in v or "NO-PIE" in v:
                flags += ["-fno-pie", "-no-pie"]
            elif "PIE ENABLED" in v or "ENABLED" in v:
                flags += ["-fPIE", "-pie"]

    seen = set()
    out = []
    for f in flags:
        if f not in seen:
            out.append(f)
            seen.add(f)
    return out


def discover_targets(selected: list[str]) -> list[str]:
    """
    Finding all the targets in the benchmarks/ directory.
    """
    if not BENCHMARKS.exists():
        return []
    all_targets = sorted([p.name for p in BENCHMARKS.iterdir() if p.is_dir()])
    if not selected:
        return all_targets
    return [t for t in selected if t in all_targets]


def compile_one(target: str, opt: str) -> bool:
    """
    Target compilation.
    """
    tdir = BENCHMARKS / target
    src_dir = tdir / "src"
    if not src_dir.exists():
        print(f"[SKIP] {target}: missing src/")
        return False

    src_files = sorted([p for p in src_dir.iterdir() if p.suffix.lower() in (".c", ".cpp", ".cc", ".cxx")])
    if not src_files:
        print(f"[SKIP] {target}: no C/C++ source code found in src/")
        return False

    is_cpp = any(p.suffix.lower() in (".cpp", ".cc", ".cxx") for p in src_files)
    compiler = "clang++" if is_cpp else "clang"

    out_dir = tdir / "bins" / "bin_coverage"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_bin = out_dir / target

    base_flags = [
        f"-{opt}",
        "-g",
        "-fno-omit-frame-pointer",
	    "-Wno-implicit-function-declaration",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
    ]
    prot_flags = parse_protections_flags(src_dir)

    cmd = [compiler, *base_flags, *prot_flags, *[str(p) for p in src_files], "-o", str(out_bin)]

    print(f"[+] {target}: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print(f"[ERR] '{compiler}' not found in PATH.")
        return False

    if res.returncode != 0:
        print(f"[ERR] {target}: compilation failed")
        if res.stdout.strip():
            print(res.stdout)
        if res.stderr.strip():
            print(res.stderr)
        return False

    out_bin.chmod(0o755)
    print(f"[OK]  {target}: wrote {out_bin}")
    return True


def main():
    """
    Compiles all the targets in benchmarks/ directory for the observer script.
    The goal is to generate a binary to be used as a common coverage testing ground for all the fuzzers.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="*", help="If empty, compiles all targets in benchmarks/")
    ap.add_argument("--opt", choices=["O1", "O2"], default="O2", help="Clang optimization level (default: O2)")
    args = ap.parse_args()

    targets = discover_targets(args.targets)
    if not targets:
        print("[ERR] No target found.")
        return 1

    ok, bad = [], []
    for t in targets:
        (ok if compile_one(t, args.opt) else bad).append(t)

    print("\n=== SUMMARY ===")
    print(f"Successes: {len(ok)}: {', '.join(ok) if ok else '(none)'}")
    print(f"Failures: {len(bad)}: {', '.join(bad) if bad else '(none)'}")
    return 0 if not bad else 2


if __name__ == "__main__":
    raise SystemExit(main())
