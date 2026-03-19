#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path
import argparse

def ensure_tools():
    """
    Checks if the required tools are available in the PATH.
    """
    for tool in ("llvm-profdata", "llvm-cov"):
        try:
            r = subprocess.run([tool, "--version"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               check=False)
        except FileNotFoundError:
            print(f"[-] Tool not found in PATH: {tool}", file=sys.stderr)
            sys.exit(1)
        if r.returncode != 0:
            print(f"[-] Tool not working: {tool}", file=sys.stderr)
            sys.exit(1)

def find_repo_root() -> Path:
    """
    Finds the root directory of the repository.
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parent,
        here.parent.parent,
        here.parent.parent.parent,
        Path.cwd().resolve(),
    ]
    for c in candidates:
        if (c / "benchmarks").is_dir() and (c / "results").is_dir():
            return c
    print("[-] Cannot locate repo root (need benchmarks/ and results/).", file=sys.stderr)
    sys.exit(1)

def iter_queue_inputs(queue_dir: Path):
    """
    Iterates over the input files in the queue directory.
    """
    for p in sorted(queue_dir.iterdir()):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.startswith("."):
            continue
        if name.endswith(".txt") or name == "readme.txt":
            continue
        yield p


def generate_json_summary(coverage_binary, profdata_file, output_file, summary_only=True):
    """
    Generates the json summary file from |coverage_binary| and |profdata_file|.
    """
    command = [
        'llvm-cov',
        'export',
        '-format=text',
        '-num-threads=1',
        '-region-coverage-gt=0',
        '-skip-expansions',
        coverage_binary,
        f'-instr-profile={profdata_file}',
    ]

    if summary_only:
        command.append('-summary-only')

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as dst_file:
        result = subprocess.run(command, stdout=dst_file, stderr=subprocess.PIPE, text=True)
    return result


def compute_cov_for_queue(target_bin: Path, queue_dir: Path, out_json: Path, use_file: bool,timeout_s: float = 2.0) -> bool:
    """
    Computes the coverage for the given queue directory.
    """
    inputs = list(iter_queue_inputs(queue_dir))
    if not inputs:
        out_json.write_text(json.dumps({
            "status": "empty_queue",
            "queue": str(queue_dir),
            "binary": str(target_bin),
        }, indent=2))
        return True

    env = os.environ.copy()
    executed = 0
    timeouts = 0
    errors = 0

    with tempfile.TemporaryDirectory(prefix="cov_work_") as tmp:
        work = Path(tmp)
        env["LLVM_PROFILE_FILE"] = str(work / "prof-%p.profraw")
        merged = work / "merged.profdata"

        for inp in inputs:
            try:
                if use_file:
                    cmd = [str(target_bin), str(inp)]
                    subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env=env,
                        timeout=timeout_s,
                        check=False,
                    )
                else:
                    with open(inp, "rb") as f:
                        subprocess.run(
                            [str(target_bin)],
                            stdin=f,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            env=env,
                            timeout=timeout_s,
                            check=False,
                        )
                executed += 1
            except subprocess.TimeoutExpired:
                timeouts += 1
            except Exception:
                errors += 1

        profraws = list(work.glob("prof-*.profraw"))
        if not profraws:
            out_json.write_text(json.dumps({
                "status": "no_profraw",
                "queue": str(queue_dir),
                "binary": str(target_bin),
            }, indent=2))
            return True

        subprocess.run(
            ["llvm-profdata", "merge", "-sparse", *map(str, profraws), "-o", str(merged)],
            check=True
        )

        # Uses the llvm-cov export to generate the coverage JSON
        generate_json_summary(target_bin, merged, out_json)
        # Reads the generated JSON file and extract necessary data (totals only)
        with open(out_json, 'r', encoding='utf-8') as f:
            content = json.load(f)
        # If there's "totals" data, extract and process it
        if "data" in content:
            totals = content["data"][0].get("totals", {})

            # Prepares a simplified JSON with only the percentages and covered data
            # This is used to generate the JSON file for the observer script
            simplified_data = {
                "branches_percent": totals.get("branches", {}).get("percent", 0),
                "branches_covered": totals.get("branches", {}).get("covered", 0),
                "functions_percent": totals.get("functions", {}).get("percent", 0),
                "functions_covered": totals.get("functions", {}).get("covered", 0),
                "instantiations_percent": totals.get("instantiations", {}).get("percent", 0),
                "instantiations_covered": totals.get("instantiations", {}).get("covered", 0),
                "lines_percent": totals.get("lines", {}).get("percent", 0),
                "lines_covered": totals.get("lines", {}).get("covered", 0),
                "mcdc_percent": totals.get("mcdc", {}).get("percent", 0),
                "mcdc_covered": totals.get("mcdc", {}).get("covered", 0),
                "regions_percent": totals.get("regions", {}).get("percent", 0),
                "regions_covered": totals.get("regions", {}).get("covered", 0),
            }

            with open(out_json, 'w', encoding='utf-8') as f:
                json.dump(simplified_data, f, indent=2)

        return True


def main():
    """
    Observer script to retrieve the coverage information from the fuzzer results.
    The coverege is computed on a common binary base for all the fuzzers.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Name of the target del target")
    ap.add_argument("--file", action="store_true",help="Passes input as a file")
    ap.add_argument("--qemu-mode", action="store_true", help="Process only -qemu result directories")
    args = ap.parse_args()

    repo = find_repo_root()
    target = args.target

    # Definies the base of the results and the path of the coverage binary
    results_base = repo / "results" / target
    cov_bin = repo / "benchmarks" / target / "bins" / "bin_coverage" / target
    if not results_base.is_dir():
        print(f"[-] Missing results dir: {results_base}", file=sys.stderr)
        sys.exit(1)
    if not cov_bin.is_file():
        print(f"[-] Missing coverage binary: {cov_bin}", file=sys.stderr)
        sys.exit(1)

    # Assures that the necessary tools are available
    ensure_tools()

    found = 0
    written = 0

    for root, dirs, _ in os.walk(results_base):
        # Considers only directories that contain the queue
        if "queue" not in dirs:
            continue

        root_p = Path(root)

        # Due to future changes in the structure of the results, 
        # the variant directory is the parent of root_p
        # e.g. results/<target>/<fuzzer>/<variant>/fuzzer_s0
        variant_dir = root_p.parent
        is_qemu_variant = variant_dir.name.endswith("-qemu")

        if args.qemu_mode and not is_qemu_variant:
            continue
        if not args.qemu_mode and is_qemu_variant:
            continue

        queue_dir = root_p / "queue"
        out_json = root_p / "cov_info.json"

        print(f"\n[+] Fuzzer instance → {root_p}")
        found += 1
        if compute_cov_for_queue(cov_bin, queue_dir, out_json, args.file):
            written += 1

    print("\n=== SUMMARY ===")
    print(f"Queue trovate : {found}")
    print(f"JSON scritti  : {written}")
    print("[OK] Done.")

if __name__ == "__main__":
    main()
