#!/usr/bin/env python3
import os
import sys
import yaml
import time
import docker
import threading


# ============================================================
# Utility
# ============================================================

def load_conf(path=None):
    """
    Loads configuration from config.yaml.

    If no path is provided, defaults to config.yaml in the current directory.
    """
    here = os.path.dirname(__file__)
    cfg = path or os.path.join(here, "config.yaml")

    if os.path.exists(cfg):
        with open(cfg, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    return {}


def stream_logs(container, prefix, stop_event):
    """
    Streams container logs in real time.

    Stops when stop_event is set.
    """
    try:
        for ln in container.logs(stream=True, follow=True):
            if stop_event.is_set():
                break

            try:
                decoded = ln.decode(errors="ignore").rstrip("\n")
            except:
                decoded = str(ln)

            if decoded.strip():
                print(f"[{prefix}] {decoded}")
                sys.stdout.flush()

    except Exception as e:
        print(f"[{prefix}] log stream ended: {e}")


# ============================================================
# Path helpers
# ============================================================

def derive_paths_from_arg(arg):
    """
    Resolves target name and source path from input argument.

    Supports:
        - Direct binary path (e.g., target/bin/bin_aflgo)
        - Target name only (resolved inside benchmarks directory)
    """
    arg = os.path.abspath(arg)

    # Case: binary path (contains /bin/)
    if os.path.exists(arg) and "/bin/" in arg.replace("\\", "/"):
        parts = arg.replace("\\", "/").split("/")
        try:
            idx = len(parts) - parts[::-1].index("bin") - 1
            target_name = parts[idx - 1]
            bench_dir = "/".join(parts[:idx - 1 + 1])
            src_path = os.path.join(bench_dir, "src", f"{target_name}.c")

            return target_name, os.path.abspath(src_path), os.path.abspath(os.path.dirname(src_path))
        except:
            pass

    # Case: target name only
    target_name = os.path.basename(arg)
    script_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    src_path = os.path.join(script_root, "benchmarks", target_name, "src", f"{target_name}.c")

    return target_name, os.path.abspath(src_path), os.path.dirname(os.path.abspath(src_path))


# ============================================================
# Protections + dependencies + flags
# ============================================================

def get_protections_flags(src_path):
    """
    Extracts compilation flags based on security protections.

    Reads protections_<target>.txt and converts it into compiler flags.
    """
    src_dir = os.path.dirname(src_path)
    target_name = os.path.splitext(os.path.basename(src_path))[0]
    prot_path = os.path.join(src_dir, f"protections_{target_name}.txt")

    if not os.path.isfile(prot_path):
        print(f"[!] Protection file not found: {prot_path}")
        return ""

    with open(prot_path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    flags = []

    for line in lines:
        line = " ".join(line.split())

        if line.startswith("RELRO:"):
            if "Full" in line:
                flags += ["-Wl,-z,relro", "-Wl,-z,now"]
            elif "Partial" in line:
                flags += ["-Wl,-z,relro"]

        elif line.startswith("Stack:"):
            if "No canary" not in line:
                flags += ["-fstack-protector-strong"]

        elif line.startswith("NX:"):
            if "NX enabled" not in line:
                flags += ["-z", "execstack"]

        elif line.startswith("PIE:"):
            if "PIE enabled" in line:
                flags += ["-fPIE", "-pie"]

    if flags:
        print(f"[+] Protections: {' '.join(flags)}")
        return " " + " ".join(flags)

    return ""


def load_target_files(src_path):
    """
    Loads optional configuration files:
        - dependencies.txt → system packages
        - additional_flags.txt → extra compiler flags
    """
    deps = []
    flags = []

    src_dir = os.path.dirname(src_path)
    bench_dir = os.path.dirname(src_dir)

    deps_file = os.path.join(bench_dir, "src", "dependencies.txt")
    flags_file = os.path.join(bench_dir, "src", "additional_flags.txt")

    if os.path.isfile(deps_file):
        with open(deps_file) as f:
            deps = [x.strip() for x in f if x.strip()]

    if os.path.isfile(flags_file):
        with open(flags_file) as f:
            flags = [x.strip() for x in f if x.strip()]

    return deps, flags


# ============================================================
# AFLGo runner
# ============================================================

def run_aflgo(conf, target_arg, seeds_dir, results_dir,
              timeout_s, cpuset, mem_limit, client,
              file_mode=False):
    """
    Main execution function for AFLGo fuzzing inside Docker.
    """

    image = conf.get("image", "zjuchenyuan/aflgo:latest")
    workspace_dir = conf.get("workspace_dir", "/workspace")
    aflgo_root = conf.get("aflgo_root", "/aflgo")

    target_name, src_path, src_dir = derive_paths_from_arg(target_arg)

    if not os.path.isfile(src_path):
        raise SystemExit(f"[!] Source file not found: {src_path}")

    src_name = os.path.basename(src_path)

    results_dir = os.path.abspath(results_dir)
    seeds_dir = os.path.abspath(seeds_dir)
    os.makedirs(results_dir, exist_ok=True)

    # Load optional configuration
    deps, add_flags = load_target_files(src_path)
    prot_flags = get_protections_flags(src_path)

    # Dictionary support
    dict_path = os.path.join(os.path.dirname(src_dir), target_name, "dictionary")
    has_dict = os.path.isdir(dict_path)

    # Locate autotargets.py
    here = os.path.abspath(os.path.dirname(__file__))
    candidates = [
        conf.get("autotargets_path"),
        os.path.join(here, "autotargets.py"),
        os.path.join(here, "..", "fuzzers", "aflgo", "autotargets.py"),
        "/fuzzers/aflgo/autotargets.py",
    ]

    autotargets = None
    for p in candidates:
        if p and os.path.isfile(p):
            autotargets = os.path.abspath(p)
            break

    if not autotargets:
        raise SystemExit("[!] autotargets.py not found")

    # Binary naming
    fuzz_bin_name = os.path.splitext(src_name)[0] + "_aflgo"

    # Input mode handling
    fuzz_cmd = f"./{fuzz_bin_name}"
    if file_mode:
        fuzz_cmd += " @@"

    timeout_fuzz = conf.get("fuzz_timeout", "45m")

    # ============================================================
    # ENTRYPOINT SCRIPT (executed inside container)
    # ============================================================

    entry_script = f"""
#!/bin/bash
set -e

echo "[*] Installing dependencies..."
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y python3 {" ".join(deps)} >/dev/null 2>&1 || true

cd {workspace_dir}

export AFLGO={aflgo_root}
export TMP_DIR=$PWD/aflgo_temp
mkdir -p "$TMP_DIR"

echo "[*] Running autotargets.py..."
python3 autotargets.py "{workspace_dir}/{src_name}" "$TMP_DIR"

echo "[*] Targets chosen:"
echo "----- BBtargets.txt -----"
sed -n '1,50p' "$TMP_DIR/BBtargets.txt" || true
echo "----- Ftargets.txt -----"
sed -n '1,50p' "$TMP_DIR/Ftargets.txt" || true
echo "-------------------------"

echo "[*] PHASE 1 compile..."
export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++

$CC -g -O0 -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps \
    -targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR \
    -c "{workspace_dir}/{src_name}" -o {fuzz_bin_name}.o

$CC -g -O0 -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps \
    -targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR \
    {fuzz_bin_name}.o -o {fuzz_bin_name}_temp

echo "[*] Generating distance..."
$AFLGO/scripts/genDistance.sh "$(pwd)" "$TMP_DIR" "{fuzz_bin_name}_temp"

echo "[*] PHASE 2 compile..."
$AFLGO/afl-clang-fast -distance=$TMP_DIR/distance.cfg.txt \
    -g -O0 "{workspace_dir}/{src_name}" \
    -o {fuzz_bin_name} {prot_flags} {" ".join(add_flags)}

echo "[*] Disabling network for fuzzing..."
ip link set eth0 down 2>/dev/null || true

echo "[*] Starting AFLGo fuzzing..."
AFL_NO_AFFINITY=1 $AFLGO/afl-fuzz \
    -i aflgo_in -o aflgo_out -m none -z exp -c {timeout_fuzz} \
    -- {fuzz_cmd}
"""

    # ============================================================
    # Docker configuration
    # ============================================================

    volumes = {
        os.path.abspath(src_path): {"bind": f"{workspace_dir}/{src_name}", "mode": "rw"},
        os.path.abspath(results_dir): {"bind": f"{workspace_dir}/aflgo_out", "mode": "rw"},
        os.path.abspath(seeds_dir): {"bind": f"{workspace_dir}/aflgo_in", "mode": "ro"},
        os.path.abspath(autotargets): {"bind": f"{workspace_dir}/autotargets.py", "mode": "ro"},
    }

    if has_dict:
        volumes[os.path.abspath(dict_path)] = {
            "bind": f"{workspace_dir}/dictionary",
            "mode": "ro"
        }

    cname = f"aflgo_{target_name}_{int(time.time()) % 10000}"

    container_kwargs = {
        "image": image,
        "command": ["bash", "-c", entry_script],
        "volumes": volumes,
        "working_dir": workspace_dir,
        "detach": True,
        "tty": False,
        "name": cname,
        "network_mode": "bridge",
        "cap_add": ["SYS_PTRACE", "SYS_NICE"],
        "environment": {"AFL_NO_AFFINITY": "1"},
    }

    if cpuset and str(cpuset).lower() not in ("none", "auto"):
        container_kwargs["cpuset_cpus"] = str(cpuset)

    if mem_limit and str(mem_limit).lower() != "none":
        container_kwargs["mem_limit"] = mem_limit

    print(f"[+] Launching AFLGo container: {cname}")

    cont = client.containers.run(**container_kwargs)

    # ============================================================
    # Logging thread
    # ============================================================

    stop_event = threading.Event()

    log_thread = threading.Thread(
        target=stream_logs,
        args=(cont, cname, stop_event),
        daemon=True
    )
    log_thread.start()

    start = time.time()

    # ============================================================
    # Monitoring loop
    # ============================================================

    try:
        while True:
            cont.reload()

            if cont.status != "running":
                print("[+] Container exited.")
                break

            if time.time() - start > timeout_s:
                print("[!] Timeout reached — stopping container")
                break

            time.sleep(2)

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

    print(f"[+] AFLGo run completed. Results in: {results_dir}")


# ============================================================
# Main
# ============================================================

def main():
    """
    CLI entrypoint for AFLGo runner.
    """

    if len(sys.argv) < 7:
        print("Usage: run_fuzzer.py <target_or_bin_path> <seeds> <results> "
              "<timeout_s> <cpuset> <mem_limit> [--qemu] [--file]")
        sys.exit(1)

    target_arg, seeds, results, timeout_s, cpuset, mem_limit = sys.argv[1:7]

    qemu_mode = "--qemu" in sys.argv
    file_mode = "--file" in sys.argv

    if qemu_mode:
        print("[!] AFLGo does NOT support QEMU mode — skipping.")
        sys.exit(0)

    conf = load_conf()
    client = docker.from_env()

    run_aflgo(
        conf, target_arg, seeds, results,
        int(timeout_s), cpuset, mem_limit, client,
        file_mode=file_mode
    )


if __name__ == "__main__":
    main()