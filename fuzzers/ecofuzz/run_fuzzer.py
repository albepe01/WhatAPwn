#!/usr/bin/env python3
"""
EcoFuzz Runner

Executes EcoFuzz inside a Docker container with:
    - dependency installation
    - network isolation
    - proper PID1 execution via exec
    - optional QEMU mode
"""

import os
import sys
import time
import yaml
import docker
import threading


# =============================================================
# Utility
# =============================================================

def load_conf(path="config.yaml"):
    """Loads EcoFuzz configuration."""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def load_target_files(target_path):
    """
    Loads optional target configuration:
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


def parse_cpuset(cpuset):
    """Parses CPU set configuration."""
    if not cpuset or str(cpuset).lower() in ("none", "auto"):
        return None
    return str(cpuset)


def stream_logs(container, prefix, stop_event):
    """
    Streams container logs.
    """
    try:
        for ln in container.logs(stream=True, follow=True):
            if stop_event.is_set():
                break

            decoded = ln.decode(errors="ignore").rstrip()

            # Filter noisy warnings
            if "sched_setaffinity failed" in decoded:
                continue

            print(f"[{prefix}] {decoded}")

    except Exception as e:
        print(f"[{prefix}] log stream ended: {e}")


def find_dictionary(seeds_path):
    """
    Detects optional AFL dictionary.
    """
    parent = os.path.dirname(os.path.abspath(seeds_path))
    d = os.path.join(parent, "dictionary", "dictionary.dict")
    return d if os.path.isfile(d) else None


# =============================================================
# Runner
# =============================================================

def run_ecofuzz(conf, target, seeds, results, timeout, cpuset, mem_limit, client,
                qemu_enabled=False, file_mode=False):
    """
    Runs EcoFuzz inside Docker.
    """

    os.makedirs(results, exist_ok=True)

    image = conf.get("image", "zjuchenyuan/ecofuzz")
    exec_timeout_ms = int(conf.get("exec_timeout_ms", 1000))
    poll_interval = float(conf.get("poll_interval_s", 1.0))
    env = dict(conf.get("environment", {}) or {})

    # Ensure affinity is disabled
    env["AFL_NO_AFFINITY"] = "1"

    deps, add_flags = load_target_files(target)

    # QEMU flag
    qemu_flag = "-Q" if qemu_enabled else ""

    # Target command
    target_cmd = "/workspace/target"

    if add_flags:
        target_cmd += " " + " ".join(add_flags)

    if file_mode:
        target_cmd += " @@"

    # Volume mapping
    volumes = {
        os.path.abspath(target):  {"bind": "/workspace/target", "mode": "ro"},
        os.path.abspath(seeds):   {"bind": "/workspace/seeds",  "mode": "ro"},
        os.path.abspath(results): {"bind": "/workspace/out",    "mode": "rw"},
    }

    # Dictionary support
    dict_path = find_dictionary(seeds)
    dict_arg = ""

    if dict_path:
        volumes[os.path.dirname(dict_path)] = {"bind": "/workspace/dictionary", "mode": "ro"}
        dict_arg = "-x /workspace/dictionary/dictionary.dict"

    # Export environment for bash execution
    def quote(v):
        return "'" + str(v).replace("'", "'\"'\"'") + "'"

    env_export = " ".join(f"{k}={quote(v)}" for k, v in env.items())

    # Build EcoFuzz command
    cmd = (
        f"{env_export} ./afl-fuzz {qemu_flag} {dict_arg} "
        f"-m none -i /workspace/seeds -o /workspace/out "
        f"-t {exec_timeout_ms}+ -- {target_cmd}"
    )

    cname = f"ecofuzz_{'qemu' if qemu_enabled else 'llvm'}_{int(time.time()) % 10000}"

    print(f"[+] Launching EcoFuzz: {cname}")
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

echo "[*] Starting EcoFuzz..."
exec env AFL_NO_AFFINITY=1 {cmd}
"""

    container_kwargs = {
        "image": image,
        "command": ["bash", "-c", entry_script],
        "volumes": volumes,
        "working_dir": "/EcoFuzz",
        "detach": True,
        "name": cname,
        "network_mode": "bridge",
        "cap_add": ["SYS_PTRACE", "SYS_NICE"],
        "environment": env,
    }

    if cpuset:
        container_kwargs["cpuset_cpus"] = str(cpuset)

    if mem_limit and mem_limit.lower() != "none":
        container_kwargs["mem_limit"] = mem_limit

    cont = client.containers.run(**container_kwargs)

    # Logging
    stop_event = threading.Event()
    threading.Thread(
        target=stream_logs,
        args=(cont, cname, stop_event),
        daemon=True
    ).start()

    # Monitor loop
    start_time = time.time()

    try:
        while True:
            cont.reload()

            if cont.status != "running":
                print("[+] EcoFuzz container exited")
                break

            if time.time() - start_time > timeout:
                print("[!] Timeout reached")
                break

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("[!] Interrupted")

    finally:
        stop_event.set()

        try: cont.stop(timeout=5)
        except: pass

        try: cont.remove(force=True)
        except: pass

    print(f"[+] EcoFuzz finished. Results in {results}")


# =============================================================
# Entry point
# =============================================================

def main():
    """CLI entrypoint."""
    if len(sys.argv) < 7:
        print("Usage: run_fuzzer.py <target> <seeds> <results> <timeout> <cpuset> <mem> [--qemu] [--file]")
        sys.exit(1)

    target, seeds, results, timeout, cpuset, mem_limit = sys.argv[1:7]

    qemu_enabled = "--qemu" in sys.argv
    file_mode = "--file" in sys.argv

    conf = load_conf()
    client = docker.from_env()

    run_ecofuzz(
        conf, target, seeds, results,
        int(timeout), parse_cpuset(cpuset), mem_limit, client,
        qemu_enabled=qemu_enabled,
        file_mode=file_mode
    )


if __name__ == "__main__":
    main()