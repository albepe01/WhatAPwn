#!/usr/bin/env python3

import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCHMARKS = ROOT.parent / "benchmarks"

DOCKER_IMAGE_DEFAULT = "aflplusplus/aflplusplus:latest"
DOCKER_IMAGE_OLD_AFL = "zjuchenyuan/afl:unibench"


def get_protections_flags(src_dir: Path, use_old_afl=False):
    """
    Retrives the protections flags from the protections_<target>.txt file.
    """
    target_name = src_dir.parent.name
    prot_file = src_dir / f"protections_{target_name}.txt"
    if not prot_file.exists():
        return []

    raw_lines = [l.strip() for l in prot_file.open("r", encoding="utf-8") if l.strip()]
    flags = []
    for line in raw_lines:
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip().upper()
            val = val.strip()
        else:
            key = "UNKNOWN"
            val = line

        if key == "RELRO":
            if "FULL" in val.upper():
                flags += ["-Wl,-z,relro", "-Wl,-z,now"]
            elif "PARTIAL" in val.upper():
                flags += ["-Wl,-z,relro"]
        elif key == "STACK":
            if "NO CANARY" in val.upper():
                flags += ["-fno-stack-protector"]
            else:
                flags += ["-fstack-protector-strong"]
        elif key == "NX":
            if "ENABLED" not in val.upper():
                flags += ["-z", "execstack"]
        elif key == "PIE":
            val_up = val.upper()
            if "NO PIE" in val_up or "NO-PIE" in val_up:
                flags += ["-fno-pie"] if use_old_afl else ["-no-pie"]
            elif "PIE ENABLED" in val_up:
                flags += ["-fPIE", "-pie"]

    seen, uniq = set(), []
    for f in flags:
        if f not in seen:
            uniq.append(f)
            seen.add(f)
    return uniq


def discover_targets(selected):
    """
    Finding all the targets in the benchmarks/ directory.
    """
    if not BENCHMARKS.exists():
        print(f"[ERR] benchmarks/ not found in {BENCHMARKS}")
        return []
    all_t = sorted([p.name for p in BENCHMARKS.iterdir() if p.is_dir()])
    return all_t if not selected else [s for s in selected if s in all_t]


def compile_target(target, docker_image, out_bin_dir, use_old_afl=False, enable_asan=False, enable_cmplog=False):
    """
    Target compilation.
    """
    target_dir = BENCHMARKS / target
    src_dir = target_dir / "src"

    if not src_dir.exists():
        print(f"[ERR] {target}: src/ not found. Skipping...")
        return False

    src_files = [p.name for p in src_dir.iterdir() if p.suffix.lower() in (".c", ".cpp", ".cc", ".cxx")]
    if not src_files:
        print(f"[ERR] {target}: no source code found. Skipping...")
        return False

    out_bin_dir.mkdir(parents=True, exist_ok=True)
    is_cpp = any(s.endswith((".cpp", ".cc", ".cxx")) for s in src_files)
    compiler = "afl-clang++" if (use_old_afl and is_cpp) else \
               "afl-clang" if use_old_afl else \
               "afl-clang-fast++" if is_cpp else "afl-clang-fast"

    base_cflags = ["-O2", "-g", "-fno-omit-frame-pointer", "-Wno-implicit-function-declaration"]
    if enable_asan:
        base_cflags.append("-fsanitize=address")

    protections = get_protections_flags(src_dir, use_old_afl)
    cflags = base_cflags + protections

    outname = target
    outpath_container = f"/work/bin/{outname}"
    host_src, host_bin = str(src_dir.resolve()), str(out_bin_dir.resolve())

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{host_src}:/work/src",
        "-v", f"{host_bin}:/work/bin",
        "-w", "/work/src",
    ]
    if enable_cmplog:
        docker_cmd += ["-e", "AFL_LLVM_CMPLOG=1"]

    docker_cmd += [docker_image, compiler] + cflags + src_files + ["-o", outpath_container]

    print(f"[+] Compiling '{target}' with {docker_image} -> {out_bin_dir} (asan={enable_asan}, cmplog={enable_cmplog})")
    try:
        res = subprocess.run(docker_cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[ERR] Docker non trovato.")
        return False

    if res.returncode != 0:
        print(f"[ERR] Compilazione fallita per {target}")
        print(res.stderr)
        return False

    final_bin = out_bin_dir / outname
    if final_bin.exists():
        final_bin.chmod(0o755)
        print(f"[OK] {target} -> {final_bin}")
        return True
    return False


def main(argv):
    targets = discover_targets(argv[1:])
    if not targets:
        print("[!] No target found.")
        return 1

    success, fail = [], []
    for t in targets:
        # AFL++
        if compile_target(t, DOCKER_IMAGE_DEFAULT, BENCHMARKS / t / "bins" / "bin_aflpp"):
            success.append(f"{t} (AFL++)")
        else:
            fail.append(f"{t} (AFL++)")

        # AFL
        if compile_target(t, DOCKER_IMAGE_OLD_AFL, BENCHMARKS / t / "bins" / "bin_afl", use_old_afl=True):
            success.append(f"{t} (old AFL)")
        else:
            fail.append(f"{t} (old AFL)")

        # AFL++ with ASan
        if compile_target(t, DOCKER_IMAGE_DEFAULT, BENCHMARKS / t / "bins" / "bin_asan", enable_asan=True):
            success.append(f"{t} (AFL++ ASan)")
        else:
            fail.append(f"{t} (AFL++ ASan)")

        # AFL++ with CMPLOG
        if compile_target(t, DOCKER_IMAGE_DEFAULT, BENCHMARKS / t / "bins" / "bin_cmplog", enable_cmplog=True):
            success.append(f"{t} (AFL++ CMPLOG)")
        else:
            fail.append(f"{t} (AFL++ CMPLOG)")

    print("=== SUMMARY ===")
    print(f"Successes: {len(success)}: {', '.join(success) if success else '(none)'}")
    print(f"Failures : {len(fail)}: {', '.join(fail) if fail else '(none)'}")
    return 0 if not fail else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
