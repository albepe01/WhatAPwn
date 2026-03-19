#!/usr/bin/env python3
"""
AFL++ MOPT Runner

Uses MOpt mutation scheduling (-L 0), which dynamically optimizes
mutation strategies during fuzzing.

Features:
    - Automatic installation of dependencies.txt
    - Network disabled before fuzzing
    - AFL++ executed as PID 1 (exec)
    - Master/secondary synchronization
"""

import os
import sys
import time
import yaml
import docker
import threading
from typing import Optional, Tuple


# =============================================================
# Utility
# =============================================================

def load_conf(path: str = None):
    """Loads configuration from config.yaml."""
    here = os.path.dirname(__file__)
    cfg_path = path or os.path.join(here, "config.yaml")

    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    return {}


def load_target_files(target_path: str):
    """
    Loads optional target-specific configuration:
        - dependencies.txt
        - additional_flags.txt
    """
    deps = []
    flags = []

    root = os.path.dirname(os.path.dirname(os.path.abspath(target_path)))
    src = os.path.join(root, "../src")

    deps_file = os.path.join(src, "dependencies.txt")
    flags_file = os.path.join(src, "additional_flags.txt")

    if os.path.isfile(deps_file):
        with open(deps_file) as f:
            deps = [x.strip() for x in f if x.strip()]

    if os.path.isfile(flags_file):
        with open(flags_file) as f:
            flags = [x.strip() for x in f if x.strip()]

    return deps, flags


def stream_logs(container, prefix: str, stop_event: threading.Event):
    """
    Streams container logs while filtering common AFL++ noise.
    """
    try:
        for ln in container.logs(stream=True, follow=True):
            if stop_event.is_set():
                break

            try:
                decoded = ln.decode(errors="ignore").rstrip("\n")
            except:
                decoded = str(ln)

            if (
                "Uh-oh" in decoded
                or "CPU cores on your system are allocated" in decoded
                or "setaffinity failed to CPU" in decoded
            ):
                continue

            print(f"[{prefix}] {decoded}")

    except Exception as e:
        print(f"[{prefix}] log stream ended: {e}")


def find_dictionary(seeds_path: str):
    """
    Detects optional dictionary near seeds directory.
    """
    try:
        seeds_abs = os.path.abspath(seeds_path)
        parent = os.path.dirname(seeds_abs)
        d = os.path.join(parent, "dictionary", "dictionary.dict")

        if os.path.isfile(d):
            return d, "dictionary.dict"
    except:
        pass

    return None


def decide_role(results_dir: str):
    """
    Determines MASTER (-M) or SECONDARY (-S) role using lock file.
    """
    os.makedirs(results_dir, exist_ok=True)

    root = os.path.dirname(os.path.dirname(results_dir))
    lockfile = os.path.join(root, ".aflpp_master.lock")

    try:
        fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)

        print("[+] MASTER: -M fuzzer_main")
        return "-M", "fuzzer_main"

    except FileExistsError:
        pass

    existing = [d for d in os.listdir(results_dir) if d.startswith("fuzzer_s")]

    max_idx = -1
    for d in existing:
        try:
            idx = int(d[8:])
            max_idx = max(max_idx, idx)
        except:
            pass

    sec_name = f"fuzzer_s{max_idx + 1}"
    print(f"[+] SECONDARY: -S {sec_name}")

    return "-S", sec_name


# =============================================================
# Runner
# =============================================================

def run_aflpp(conf,
              target,
              seeds,
              results,
              timeout_s,
              core,
              mem_limit,
              qemu_mode,
              file_mode):
    """
    Runs AFL++ using MOpt mutation optimization inside Docker.
    """

    image = conf.get("image", "aflplusplus/aflplusplus:latest")
    exec_timeout_ms = int(conf.get("exec_timeout_ms", 1000))

    deps, add_flags = load_target_files(target)
    env = dict(conf.get("environment", {}) or {})

    # Select MOPT variant
    variant_key = "variant_list_qemu" if qemu_mode else "variant_list_llvm"
    variants = conf.get(variant_key, [])

    if not variants:
        raise SystemExit(f"[!] No variants in {variant_key}")

    selected = variants[0]
    base_args = (selected.get("args") or "").strip()
    env.update(selected.get("env", {}) or {})

    # Mount volumes
    volumes = {
        os.path.abspath(target): {"bind": "/workspace/target", "mode": "ro"},
        os.path.abspath(seeds): {"bind": "/workspace/seeds", "mode": "ro"},
        os.path.abspath(results): {"bind": "/workspace/out", "mode": "rw"},
    }

    # Dictionary support
    dict_info = find_dictionary(seeds)
    dict_arg = ""

    if dict_info:
        path, fname = dict_info
        volumes[os.path.dirname(path)] = {"bind": "/workspace/dictionary", "mode": "ro"}
        dict_arg = f"-x /workspace/dictionary/{fname}"
        print(f"[+] Using dictionary: {path}")

    # Master / secondary role
    role_flag, role_name = decide_role(results)

    # Build target command
    target_cmd = "/workspace/target"

    if add_flags:
        target_cmd += " " + " ".join(add_flags)

    if file_mode:
        target_cmd += " @@"

    # Build afl-fuzz command
    parts = ["afl-fuzz"]

    if base_args:
        parts.append(base_args)

    if dict_arg:
        parts.append(dict_arg)

    parts.extend([
        role_flag,
        role_name,
        "-i /workspace/seeds",
        "-o /workspace/out",
        f"-t {exec_timeout_ms}+",
        "--",
        target_cmd
    ])

    cmd = " ".join(parts)

    mode_str = "QEMU" if qemu_mode else "LLVM"
    cname = f"aflpp_mopt_{mode_str.lower()}_{role_name}_{int(time.time()) % 10000}"

    print(f"[+] Running MOPT: mode={mode_str}, role={role_flag} {role_name}")
    print(f"[+] CMD: {cmd}")

    # Entry script
    entry_script = f"""
    #!/bin/bash
    set -e

    echo "[*] Installing dependencies..."
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y {" ".join(deps)} >/dev/null 2>&1 || true

    echo "[*] Disabling network..."
    ip link set eth0 down 2>/dev/null || true

    echo "[*] Starting AFL++ MOPT..."
    exec {cmd}
    """

    client = docker.from_env()

    container_kwargs = {
        "image": image,
        "command": ["bash", "-c", entry_script],
        "volumes": volumes,
        "cap_add": ["SYS_PTRACE", "SYS_NICE"],
        "network_mode": "bridge",
        "detach": True,
        "environment": env,
        "name": cname,
        "cpuset_cpus": str(core),
    }

    if mem_limit.lower() != "none":
        container_kwargs["mem_limit"] = mem_limit

    cont = client.containers.run(**container_kwargs)

    stop_event = threading.Event()
    threading.Thread(
        target=stream_logs, args=(cont, cname, stop_event), daemon=True
    ).start()

    start = time.time()

    try:
        while True:
            if time.time() - start > timeout_s:
                print(f"[!] Timeout reached ({timeout_s}s)")
                break

            cont.reload()

            if cont.status != "running":
                print("[+] Container exited")
                break

            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Interrupted by user")

    finally:
        stop_event.set()

        try: cont.stop(timeout=5)
        except: pass

        try: cont.remove(force=True)
        except: pass

    print(f"[+] AFL++ MOPT finished, results at {results}")

    # Cleanup lock
    try:
        if role_flag == "-M":
            root = os.path.dirname(os.path.dirname(results))
            os.remove(os.path.join(root, ".aflpp_master.lock"))
            print("[+] Lockfile removed")
    except:
        pass


# =============================================================
# Entry Point
# =============================================================

def main():
    """CLI entrypoint."""
    if len(sys.argv) < 7:
        print("Usage: run_fuzzer.py <target> <seeds> <results> <timeout> <core> <mem> [--qemu] [--file]")
        sys.exit(1)

    target, seeds, results, timeout_s, core_s, mem = sys.argv[1:7]
    qemu = "--qemu" in sys.argv
    file_mode = "--file" in sys.argv

    run_aflpp(
        load_conf(),
        target,
        seeds,
        results,
        int(timeout_s),
        int(core_s),
        mem,
        qemu,
        file_mode,
    )


if __name__ == "__main__":
    main()