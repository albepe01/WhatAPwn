#!/usr/bin/env python3
import os
import sys
import yaml
import subprocess
import signal
import time
import shutil

BENCH_DIR = "benchmarks"
RESULTS_DIR = "results"

active_processes = []

def sigint_handler():
    """
    Sends SIGINT to all active processes. This is used to stop fuzzing in a clean way.
    """
    print("\n[!] Caught Ctrl-C — stopping all fuzzer processes...")
    for p in active_processes:
        try:
            p.send_signal(signal.SIGINT)
        except Exception:
            pass
    time.sleep(3)
    # removing active processes
    for p in active_processes:
        if p.poll() is None:  
            try:
                p.terminate() 
            except Exception:
                pass
    time.sleep(1)
    for p in active_processes:
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
    print("[+] All fuzzers terminated.")
    sys.exit(1)

signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTERM, sigint_handler)

def safe_clear_dir(path):
    """
    Removes ONLY the variant directory.
    Safety check based on base_dir.
    """
    if RESULTS_DIR not in os.path.abspath(path):
        print(f"[!] Unsafe delete blocked: {path}")
        return

    if os.path.isdir(path):
        print(f"[+] Clearing: {path}")
        shutil.rmtree(path, ignore_errors=True)

    os.makedirs(path, exist_ok=True)

def main():
    """
    Framework orchestrator script for fuzzing.
    """
    if len(sys.argv) < 2:
        print("Usage: run_fuzzers.py <target> [--qemu] [--file]")
        sys.exit(1)

    target = sys.argv[1]
    qemu_flag = "--qemu" in sys.argv    # emulation mode with qemu
    file_flag = "--file" in sys.argv    # read input from file

    # Loading the config file
    if not os.path.exists("fuzzing_config.yaml"):
        print("[!] Missing fuzzing_config.yaml")
        sys.exit(1)
    with open("fuzzing_config.yaml", "r") as f:
        cfg = yaml.safe_load(f)

    if not qemu_flag:
        fuzzers_cfg = cfg.get("fuzzers", {})
    else:
        fuzzers_cfg = cfg.get("fuzzers-qemu", {})
    global_timeout = cfg.get("global_timeout", None)

    target_dir = os.path.join(BENCH_DIR, target)
    if not os.path.isdir(target_dir):
        print(f"[!] Target directory not found: {target_dir}")
        sys.exit(1)

    seeds_dir = os.path.join(target_dir, "seeds")
    if not os.path.isdir(seeds_dir):
        print(f"[!] Seeds directory not found: {seeds_dir}")
        sys.exit(1)

    host_cores = os.cpu_count()
    next_core = 0

    # Looping through fuzzers
    for fuzzer_name, params in fuzzers_cfg.items():

        bin_subpath = params.get("path")
        if not bin_subpath:
            print(f"[!] No 'path' specified for fuzzer {fuzzer_name}")
            continue

        bin_dir = os.path.join(target_dir, bin_subpath)
        if not os.path.isdir(bin_dir):
            print(f"[!] Bin directory not found: {bin_dir}")
            continue

        # Choose the first executable in the directory
        target_bin = None
        for f in os.listdir(bin_dir):
            full = os.path.join(bin_dir, f)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                target_bin = full
                break

        if not target_bin:
            print(f"[!] No executable found in {bin_dir}")
            continue

        # Timeout logic
        specific_timeout = params.get("timeout", None)
        global_timeout = cfg.get("global_timeout", None)
        if isinstance(specific_timeout, str) and specific_timeout.lower() == "none":
            specific_timeout = None
        if isinstance(global_timeout, str) and global_timeout.lower() == "none":
            global_timeout = None
        # Using the specific timeout if specified
        if specific_timeout is not None:
            timeout = specific_timeout
        else:
            timeout = global_timeout
        # If the global timeout is None, set it to infinity
        if timeout is None:
            timeout = 999999999

        timeout = int(timeout)
        mem_limit = params.get("mem_limit", "none")

        # CPU core allocation
        if next_core >= host_cores:
            print(f"[!] No free CPU core available for {fuzzer_name}, skipping")
            continue
        core = next_core
        next_core += 1

        # VARIANT DIRECTORY for emulation mode with qemu
        fuzzer_dir = os.path.join(RESULTS_DIR, target, fuzzer_name)
        variant = f"{fuzzer_name}-qemu" if qemu_flag else fuzzer_name
        final_dir = os.path.join(fuzzer_dir, variant)
        safe_clear_dir(final_dir, RESULTS_DIR)

        # Launching the specific runner script
        script_path = os.path.join("fuzzers", fuzzer_name, "run_fuzzer.py")
        if not os.path.exists(script_path):
            print(f"[!] Missing runner script: {script_path}")
            continue
        cmd = [
            "python3", script_path,
            target_bin,
            seeds_dir,
            final_dir,
            str(timeout),
            str(core),
            str(mem_limit),
        ]
        if qemu_flag:
            cmd.append("--qemu")
        if file_flag:
            cmd.append("--file")
        print(f"\n[+] Launching {fuzzer_name} on core {core}")
        print("    CMD:", " ".join(cmd))
        proc = subprocess.Popen(cmd)
        active_processes.append(proc)

    print("\n[+] All fuzzers started. Waiting... (Ctrl-C to stop all)")

    try:
        for p in active_processes:
            p.wait()
    except KeyboardInterrupt:
        sigint_handler(None, None)
    print("[+] All fuzzers finished.")

    # Calling the observer script to generate the coverage reports
    observer_cmd = ["python3", "observer_cov.py", target]
    if qemu_flag:
        observer_cmd.append("--qemu-mode")
    if file_flag:           
        observer_cmd.append("--file")
    print(f"[observer] Running: {' '.join(observer_cmd)}")
    subprocess.run(observer_cmd)

if __name__ == "__main__":
    main()
