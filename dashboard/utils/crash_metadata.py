import os
import json

from dashboard.utils.crash_loader import list_crashes_for_program, find_crash_dir


# Mapping of ASAN/QASAN error types to short, user-friendly abbreviations
ERROR_MAP = {
    "heap-use-after-free": "UAF",
    "heap-buffer-overflow": "Heap OOB",
    "stack-buffer-overflow": "Stack OOB",
    "stack-overflow": "Stack OOB",
    "global-buffer-overflow": "Global OOB",
    "stack-use-after-scope": "UAS",
    "stack-use-after-return": "UAR",
    "heap-memory-leak": "HML",
    "segv": "SEGV",             # Sometimes appears in lowercase
    "attempting": "Double Free",
}

# Color mapping for exploitable classification (CERT exploitable)
EXPLOITABLE_COLORS = {
    "EXPLOITABLE": "red",
    "PROBABLY_EXPLOITABLE": "orange",
    "PROBABLY_NOT_EXPLOITABLE": "yellow",
    "NOT_EXPLOITABLE": "green",
    "UNKNOWN": "grey",
}

# Color mapping for ASAN/QASAN vulnerability types
ASAN_COLORS = {
    "UAF": "red",
    "Double Free": "red",
    "Heap OOB": "orange",
    "Stack OOB": "orange",
    "Global OOB": "orange",
    "HML": "yellow",
    "UAS": "yellow",
    "UAR": "yellow",
    "SEGV": "yellow",
    "UNKNOWN": "grey",
}


def load_json_safe(path):
    """
    Safely loads a JSON file.

    Returns:
        - Parsed JSON object if successful
        - None if file does not exist or parsing fails
    """
    if not path or not os.path.isfile(path):
        return None

    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return None


def find_json_with_prefix(dir_path, prefix_list):
    """
    Returns the path of the first JSON file in the directory
    whose filename starts with one of the given prefixes.
    """
    if not os.path.isdir(dir_path):
        return None

    for fname in os.listdir(dir_path):
        for pref in prefix_list:
            if fname.lower().startswith(pref.lower()) and fname.lower().endswith(".json"):
                return os.path.join(dir_path, fname)

    return None


def load_crash_metadata(program: str, results_root="results"):
    """
    Returns a list of dictionaries containing enriched crash metadata:

        - classification (from exploitable)
        - classification_color
        - vuln_abbr (from ASAN/QASAN)
        - vuln_color
        - full crash path
        - raw error string
        - paths to JSON sources

    This function aggregates data from:
        - exploitable JSON reports
        - ASAN/QASAN JSON reports
    """

    crash_list = list_crashes_for_program(program, results_root)
    result = []

    for full_name in crash_list:

        # Resolve actual crash directory
        base_path = find_crash_dir(program, full_name, results_root)

        if base_path is None:
            # If crash directory cannot be found, still return a placeholder entry
            result.append({
                "name": full_name,
                "classification": "UNKNOWN",
                "classification_color": "grey70",
                "vuln_abbr": "UNKNOWN",
                "vuln_color": "grey70",
                "error_raw": "UNKNOWN",
                "paths": {
                    "exploitable": None,
                    "asan_or_qasan": None,
                }
            })
            continue

        # --- Load exploitable JSON ---
        exploitable_path = find_json_with_prefix(base_path, ["exploitable"])
        exploitable = load_json_safe(exploitable_path)

        # --- Load ASAN/QASAN JSON ---
        asan_path = find_json_with_prefix(base_path, ["asan", "qasan"])
        asan = load_json_safe(asan_path)

        # --- Extract classification ---
        classification = ""

        if exploitable:
            # CERT exploitable uses lowercase "classification" field
            classification = exploitable.get("classification", "").upper()

        if not classification:
            classification = "UNKNOWN"

        classification_color = EXPLOITABLE_COLORS.get(classification, "grey70")

        # --- Extract ASAN/QASAN error ---
        error_raw = ""

        if asan:
            error_raw = asan.get("error", "")

        if not error_raw:
            error_raw = "UNKNOWN"

        # Convert to short label
        vuln_abbr = ERROR_MAP.get(error_raw, error_raw.upper())

        # Resolve color for vulnerability type
        vuln_color = ASAN_COLORS.get(vuln_abbr, "grey70")

        # --- Build final metadata entry ---
        result.append({
            "name": full_name,  # Format: fuzzer/variant/crashname
            "classification": classification,
            "classification_color": classification_color,
            "vuln_abbr": vuln_abbr,
            "vuln_color": vuln_color,
            "error_raw": error_raw,
            "paths": {
                "exploitable": exploitable_path,
                "asan_or_qasan": asan_path,
            }
        })

    return result