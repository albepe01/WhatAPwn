#!/usr/bin/env python3
import os
import argparse
import shutil
import subprocess
import hashlib 

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

RESULTS_DIR = os.path.join(BASE_DIR, "results")
BENCH_DIR   = os.path.join(BASE_DIR, "benchmarks")
TRIAGE_DIR  = os.path.join(BASE_DIR, "triaging")


def select_bin(bin_name, qemu_mode):
    """
    Selects the mode of triage based on the available binaries.
    """
    asan_bin  = os.path.join(BENCH_DIR, bin_name, "bins", "bin_asan", bin_name)
    qemu_bin  = os.path.join(BENCH_DIR, bin_name, "bin_original", bin_name)

    if not qemu_mode:
        return "asan", asan_bin
    else:
        return "qemu", qemu_bin


def compute_crash_hash(case_dir):
    """
    Computes a SHA-256 hash combining ONLY the .log files:
    - *.log
    - excluding files that start with 'xxd'
    - ignoring crash input, json and any other file.
    """
    sha = hashlib.sha256()

    for root, dirs, files in os.walk(case_dir):
        for f in sorted(files):
            lower = f.lower()

            if not lower.endswith(".log"):
                continue

            if lower.startswith("xxd"):
                continue

            fp = os.path.join(root, f)
            try:
                with open(fp, "rb") as fh:
                    sha.update(fh.read())
            except:
                pass

    return sha.hexdigest()


def run_triagers(mode, crash_input, outdir, bin_name, file_flag):
    """
    Executes the triagers using the correct binaries based on the minimal logic.
    Performs a further hash-based deduplication, if enabled.
    """
    scripts = {
        "asan":  os.path.join(TRIAGE_DIR, "asan_triage.py"),
        "qasan": os.path.join(TRIAGE_DIR, "qasan_triage.py"),
        "expl":  os.path.join(TRIAGE_DIR, "exploitable_triage.py"),
        "xxd":   os.path.join(TRIAGE_DIR, "xxd_triage.py"),
    }

    asan_bin = os.path.join(BENCH_DIR, bin_name, "bins", "bin_asan", bin_name)
    qemu_bin = os.path.join(BENCH_DIR, bin_name, "bin_original", bin_name)

    if mode == "asan":
        order = ["asan", "expl", "xxd"]
    elif mode == "qemu":
        order = ["qasan", "expl", "xxd"]
    else:
        return

    for key in order:
        script = scripts[key]

        def build_cmd(base_cmd):
            if file_flag:
                return base_cmd + ["--file"]
            return base_cmd

        # Asan
        if key == "asan":
            triage_bin = asan_bin if os.path.isfile(asan_bin) else qemu_bin
            if not os.path.isfile(triage_bin):
                print(f"[!] Binario non trovato per ASAN: {triage_bin}")
                continue

            cmd = build_cmd([
                "python3", script,
                "--bin", triage_bin,
                "--crash", crash_input,
                "--logs", outdir
            ])
            subprocess.run(cmd)
            continue

        # QAsan
        if key == "qasan":
            triage_bin = qemu_bin
            if not os.path.isfile(triage_bin):
                print(f"[!] Binario non trovato per QASAN: {triage_bin}")
                continue

            cmd = build_cmd([
                "python3", script,
                "--bin", triage_bin,
                "--crash", crash_input,
                "--logs", outdir
            ])
            subprocess.run(cmd)
            continue

        # Exploitable
        if key == "expl":
            triage_bin = qemu_bin
            if not os.path.isfile(triage_bin):
                print(f"[!] Binario exploitable non trovato: {triage_bin}")
                continue

            cmd = build_cmd([
                "python3", script,
                "--bin", triage_bin,
                "--crash", crash_input,
                "--logs", outdir
            ])
            subprocess.run(cmd)
            continue

        # Hex dump
        if key == "xxd":
            subprocess.run([
                "python3", script,
                "--crash", crash_input,
                "--out", outdir
            ])
            continue


def main():
    """
    Main triaging script. Launches specific triagers based on the available binaries.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Name of the binary")
    parser.add_argument("--qemu", action="store_true", help="QEMU support")
    parser.add_argument("--file", action="store_true", help="Propagate file mode to triagers")
    parser.add_argument("--dedup", action="store_true", help="Apply basic deduplication") 
    args = parser.parse_args()

    bin_name = args.binary
    mode, main_bin = select_bin(bin_name, args.qemu)
    if not main_bin:
        print(f"[ERRORE] No ASAN or QEMU binary found for '{bin_name}'")
        return

    print(f"[+] Mode: {mode}")
    print(f"[+] Deduplication: {'ACTIVE' if args.dedup else 'INACTIVE'}")

    base = os.path.join(RESULTS_DIR, bin_name)

    seen_hashes = set()

    for root, dirs, files in os.walk(base):
        if args.qemu:
            if "-qemu" not in root:
                continue
        else:
            if "-qemu" in root:
                continue
        if "crashes" not in dirs:
            continue

        crashes_dir = os.path.join(root, "crashes")
        triage_dir  = os.path.join(root, "triage")

        if os.path.isdir(triage_dir):
            shutil.rmtree(triage_dir)
        os.mkdir(triage_dir)

        print(f"\n[+] Fuzzing istance: {root}")
        crash_files = sorted(os.listdir(crashes_dir))
        crash_id = 0

        for f in crash_files:
            crash_path = os.path.join(crashes_dir, f)

            if not os.path.isfile(crash_path):
                continue
            if f.startswith(".") or f.lower().endswith(".txt") or f.lower()=="readme.txt":
                continue

            crash_id += 1
            case_dir = os.path.join(triage_dir, f"crash-{crash_id:03d}")
            os.mkdir(case_dir)

            shutil.copy(crash_path, os.path.join(case_dir, f))

            print(f"[+] Triage crash-{crash_id:03d}: {f}")

            run_triagers(mode, crash_path, case_dir, bin_name, args.file)

            # Deduplication
            if args.dedup:
                crash_hash = compute_crash_hash(case_dir)

                if crash_hash in seen_hashes:
                    print(f"[DEDUP] Deduplicated crash → {f}. REMOVED.")
                    shutil.rmtree(case_dir)
                    continue
                else:
                    seen_hashes.add(crash_hash)
                    print(f"[OK] Unique crash (hash={crash_hash[:12]}...)")

    print("\n[OK] Triaging completed.")


if __name__ == "__main__":
    main()
