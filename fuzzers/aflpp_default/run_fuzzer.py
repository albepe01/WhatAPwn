#!/usr/bin/env python3
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
    """
    Loads configuration from config.yaml.
    """
    here = os.path.dirname(__file__)
    cfg_path = path or os.path.join(here, "config.yaml")

    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    return {}


def load_target_files(target_path: str):
    """
    Loads optional per-target files:
        - dependencies.txt → system dependencies
        - additional_flags.txt → extra runtime arguments
    """
    deps = []
    flags = []

    root = os.path.dirname(os.path.dirname(os.path.abspath(target_path)))
    src = os.path.join(root, "../src")

    dep_file = os.path.join(src, "dependencies.txt")
    flags_file = os.path.join(src, "additional_flags.txt")

    if os.path.isfile(dep_file):
        with open(dep_file, "r") as f:
            deps = [x.strip() for x in f.readlines() if x.strip()]

    if os.path.isfile(flags_file):
        with open(flags_file, "r") as f:
            flags = [x.strip() for x in f.readlines() if x.strip()]

    return deps, flags


def stream_logs(container, prefix: str, stop_event: threading.Event):
    """
    Streams container logs while filtering noisy AFL messages.
    """
    try:
        for ln in container.logs(stream=True, follow=True):
            if stop_event.is_set():
                break

            try:
                decoded = ln.decode(errors="ignore").rstrip("\n")
            except:
                decoded = str(ln)

            # Filter common AFL++ noise
            if (
                "Uh-oh, looks like all" in decoded
                or "setaffinity failed to CPU" in decoded
                or "CPU cores on your system" in decoded
            ):
                continue

            print(f"[{prefix}] {decoded}")

    except Exception as e:
        print(f"[{prefix}] log stream ended: {e}")


def find_dictionary(seeds_path: str) -> Optional[Tuple[str, str]]:
    """
    Detects dictionary file near the seeds directory.

    Expected structure:
        seeds/
        dictionary/dictionary.dict
    """
    try:
        seeds_abs = os.path.abspath(seeds_path)
        parent = os.path.dirname(seeds_abs)
        dict_path = os.path.join(parent, "dictionary", "dictionary.dict")

        if os.path.isfile(dict_path):
            return (dict_path, "dictionary.dict")

    except:
        pass

    return None


def decide_role(results_dir: str):
    """
    Determines whether this instance is MASTER (-M) or SECONDARY (-S).

    Uses a lock file to enforce a single master instance.
    """
    os.makedirs(results_dir, exist_ok=True)

    target_root = os.path.dirname(os.path.dirname(results_dir))
    lock_path = os.path.join(target_root, ".aflpp_master.lock")

    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)

        print("[+] Lockfile created: this instance will be MASTER (-M).")
        return "-M", "fuzzer_main"

    except FileExistsError:
        pass

    # Assign next available secondary index
    existing = []

    try:
        for name in os.listdir(results_dir):
            if name.startswith("fuzzer_s"):
                existing.append(name)
    except:
        pass

    max_idx = -1
    for name in existing:
        try:
            idx = int(name[len("fuzzer_s"):])
            max_idx = max(max_idx, idx)
        except:
            continue

    next_idx = max_idx + 1
    sec_name = f"fuzzer_s{next_idx}"

    print(f"[+] Lockfile present: this instance will be SECONDARY (-S {sec_name}).")

    return "-S", sec_name


# =============================================================
# Runner
# =============================================================

def run_aflpp(conf,
              target: str,
              seeds: str,
              results: str,
              timeout_s: int,
              core: int,
              mem_limit: str,
              qemu_mode: bool = False,
              file_mode: bool = False):
    """
    Runs AFL++ inside a Docker container.
    """

    image = conf.get("image", "aflplusplus/aflplusplus:latest")
    exec_timeout_ms = int(conf.get("exec_timeout_ms", 1000))

    deps, add_flags = load_target_files(target)
    env = dict(conf.get("environment", {}) or {})

    # Select variant (LLVM or QEMU)
    variant_key = "variant_list_qemu" if qemu_mode else "variant_list_llvm"
    variants = conf.get(variant_key, [])

    if not variants:
        raise SystemExit(f"[!] No variants defined in '{variant_key}'")

    selected = variants[0]
    base_args = (selected.get("args") or "").strip()
    env.update(selected.get("env", {}) or {})

    # Docker volumes
    volumes = {
        os.path.abspath(target): {"bind": "/workspace/target", "mode": "ro"},
        os.path.abspath(seeds): {"bind": "/workspace/seeds", "mode": "ro"},
        os.path.abspath(results): {"bind": "/workspace/out", "mode": "rw"},
    }

    # Dictionary support
    dict_info = find_dictionary(seeds)
    dict_arg = ""

    if dict_info:
        host_file, filename = dict_info
        host_dir = os.path.dirname(host_file)

        volumes[os.path.abspath(host_dir)] = {
            "bind": "/workspace/dictionary",
            "mode": "ro"
        }

        dict_arg = f"-x /workspace/dictionary/{filename}"
        print(f"[+] Using dictionary: {host_file}")
    else:
        print("[+] No dictionary found")

    # Master / secondary role
    role_flag, role_name = decide_role(results)

    # Target execution command
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
    io_str = "file (@@)" if file_mode else "stdin"

    cname = f"aflpp_default_{mode_str.lower()}_{role_name}_{int(time.time()) % 10000}"

    print(f"[+] Mode: {mode_str}, IO: {io_str}, role: {role_flag} {role_name}")
    print(f"[+] Launching container {cname} -> {cmd}")

    # Container entrypoint
    entrypoint_script = f"""
    #!/bin/bash
    set -e

    echo "[*] Installing dependencies..."
    apt-get update -y && apt-get install -y {' '.join(deps)} || true

    echo "[*] Disconnecting network..."
    ip link set eth0 down 2>/dev/null || true

    echo "[*] Starting AFL++..."
    exec {cmd}
    """

    client = docker.from_env()

    container_kwargs = {
        "image": image,
        "command": ["bash", "-c", entrypoint_script],
        "volumes": volumes,
        "cap_add": ["SYS_PTRACE", "SYS_NICE"],
        "network_mode": "bridge",
        "detach": True,
        "environment": env,
        "name": cname,
        "cpuset_cpus": str(core),
        "cpuset_mems": "0",
    }

    if mem_limit and str(mem_limit).lower() != "none":
        container_kwargs["mem_limit"] = str(mem_limit)

    cont = client.containers.run(**container_kwargs)

    # Logging thread
    stop_event = threading.Event()
    log_thread = threading.Thread(
        target=stream_logs,
        args=(cont, cname, stop_event),
        daemon=True
    )
    log_thread.start()

    start_time = time.time()

    try:
        while True:
            if time.time() - start_time > timeout_s:
                print(f"[!] Timeout reached — stopping container")
                break

            cont.reload()

            if cont.status != "running":
                print("[+] Container exited.")
                break

            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Interrupted by user.")

    finally:
        stop_event.set()

        try:
            cont.stop(timeout=5)
        except:
            pass

        try:
            cont.remove(force=True)
        except:
            pass

        log_thread.join(timeout=1)

    print(f"[+] AFL++ run finished. Results saved in: {results}")

    # Cleanup lock if master
    try:
        if role_flag == "-M":
            target_root = os.path.dirname(os.path.dirname(results))
            lock_path = os.path.join(target_root, ".aflpp_master.lock")
            os.remove(lock_path)
            print("[+] Lockfile removed.")
    except:
        pass


# =============================================================
# Entry point
# =============================================================

def main():
    """
    CLI entrypoint for AFL++ runner.
    """

    if len(sys.argv) < 7:
        print("Usage: run_fuzzer.py <target> <seeds> <results> "
              "<timeout_s> <core> <mem_limit> [--qemu] [--file]")
        sys.exit(1)

    target, seeds, results, timeout_s, core_str, mem_limit = sys.argv[1:7]

    qemu_mode = "--qemu" in sys.argv
    file_mode = "--file" in sys.argv

    core = int(core_str)
    timeout_s = int(timeout_s)

    conf = load_conf()

    run_aflpp(
        conf,
        target,
        seeds,
        results,
        timeout_s,
        core,
        mem_limit,
        qemu_mode,
        file_mode
    )


if __name__ == "__main__":
    main()