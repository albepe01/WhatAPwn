import os


def list_crashes_for_program(program: str, results_root: str = "results"):
    """
    Returns a SORTED and COMPLETE list of crashes for a given program.

    Each returned element has the format:
        fuzzer/variant/crashname

    Supported directory structures:

        results/<program>/<fuzzer>/<variant>/triage/<crash>
        results/<program>/<fuzzer>/<variant>/<worker>/triage/<crash>

    where <worker> is optional and, if present, starts with 'fuzzer'.
    """

    crashes = []
    program_dir = os.path.join(results_root, program)

    # If program directory does not exist, return empty list
    if not os.path.isdir(program_dir):
        return []

    # Iterate over fuzzers (e.g., aflpp_default, aflgo, ecofuzz, ...)
    for fuzzer in sorted(os.listdir(program_dir)):
        fuzzer_path = os.path.join(program_dir, fuzzer)
        if not os.path.isdir(fuzzer_path):
            continue

        # Iterate over variants (e.g., aflpp_default, aflpp_default-qemu, aflgo, ...)
        for variant in sorted(os.listdir(fuzzer_path)):
            variant_path = os.path.join(fuzzer_path, variant)
            if not os.path.isdir(variant_path):
                continue

            triage_paths = []

            # Case 1: triage directly under the variant directory
            direct_triage = os.path.join(variant_path, "triage")
            if os.path.isdir(direct_triage):
                triage_paths.append(direct_triage)

            # Case 2: triage inside worker directories (<variant>/<worker>/triage)
            for worker in sorted(os.listdir(variant_path)):
                worker_path = os.path.join(variant_path, worker)
                if not os.path.isdir(worker_path):
                    continue

                # Only consider valid worker directories
                if not worker.startswith("fuzzer"):
                    continue

                worker_triage = os.path.join(worker_path, "triage")
                if os.path.isdir(worker_triage):
                    triage_paths.append(worker_triage)

            # Enumerate crashes from all discovered triage paths
            for triage_path in triage_paths:
                for crash_name in sorted(os.listdir(triage_path)):
                    crash_dir = os.path.join(triage_path, crash_name)
                    if os.path.isdir(crash_dir):
                        crashes.append(f"{fuzzer}/{variant}/{crash_name}")

    return crashes


def find_crash_dir(program: str, full_name: str, results_root: str = "results") -> str | None:
    """
    Given a crash identifier in the format:
        fuzzer/variant/crashname

    Returns the actual crash directory path, supporting:

        results/<program>/<fuzzer>/<variant>/triage/<crash>
        results/<program>/<fuzzer>/<variant>/<worker>/triage/<crash>

    where <worker> is optional and starts with 'fuzzer'.
    """

    try:
        fuzzer, variant, crash_name = full_name.split("/", 2)
    except ValueError:
        return None

    variant_root = os.path.join(results_root, program, fuzzer, variant)

    # Case 1: direct triage directory
    direct = os.path.join(variant_root, "triage", crash_name)
    if os.path.isdir(direct):
        return direct

    # Case 2: worker-based structure
    if os.path.isdir(variant_root):
        for worker in os.listdir(variant_root):
            worker_path = os.path.join(variant_root, worker)

            if not os.path.isdir(worker_path):
                continue

            if not worker.startswith("fuzzer"):
                continue

            candidate = os.path.join(worker_path, "triage", crash_name)
            if os.path.isdir(candidate):
                return candidate

    return None