from pathlib import Path
import time
import json

# -------------------- Default metrics --------------------

DEFAULT_METRICS = [
    "execs_per_sec",
    "total_execs",
    "saved_crashes",
    "saved_hangs",
    "corpus_count",
    "map_size",
    "edges_found",
    "coverage_ratio",
    "crashes_per_hour",
    "execs_per_input",
    "uptime",
    "stability",
    "max_depth",
    "pending_total",
    "pending_favs",
    "time_to_first_crash",
    "time_to_first_hang",
    # --- coverage metrics (llvm-cov via cov_info.json) ---
    "cov_branches_percent",
    "cov_branches_covered",
    "cov_functions_percent",
    "cov_functions_covered",
    "cov_instantiations_percent",
    "cov_instantiations_covered",
    "cov_lines_percent",
    "cov_lines_covered",
    "cov_mcdc_percent",
    "cov_mcdc_covered",
    "cov_regions_percent",
    "cov_regions_covered",
    "cov_status",
]


# -------------------- Utility --------------------

def clean_float(value):
    """
    Safely converts a value to float.

    Handles percentage strings and invalid inputs.
    Returns 0.0 on failure.
    """
    try:
        return float(str(value).replace("%", "").strip())
    except Exception:
        return 0.0


def format_time(seconds: float) -> str:
    """
    Converts seconds into a human-readable format (d, h, m, s).
    """
    try:
        seconds = int(float(seconds))
    except Exception:
        return "-"

    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    elif seconds < 86400:
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s"
    else:
        d, rem = divmod(seconds, 86400)
        h, rem2 = divmod(rem, 3600)
        m, _ = divmod(rem2, 60)
        return f"{d}d {h}h {m}m"


# -------------------- Normalization --------------------

def normalize_metrics(data: dict) -> dict:
    """
    Normalizes metric keys across different fuzzers
    (AFL, AFL++, AFLGo, EcoFuzz).
    """
    alias_map = {
        "unique_crashes": "saved_crashes",
        "unique_hangs": "saved_hangs",
        "paths_total": "corpus_count",
        "paths_found": "corpus_count",
        "uptime": "run_time",
        "bitmap_cvg": "map_size",
        "bitmap_size": "map_size",
        "execs_done": "total_execs",
        "edges_total": "edges_found",
    }

    normalized = {}
    for key, value in data.items():
        normalized[alias_map.get(key, key)] = value

    return normalized


# -------------------- plot_data parsing --------------------

def get_time_to_first_event_from_plot(plot_path: Path, event_type: str):
    """
    Extracts time to first crash or hang from plot_data.

    Supports:
        - AFL++ format (relative_time)
        - AFL / EcoFuzz / AFLGo format (unix_time)

    Handles initial measurement offset (~60 seconds).
    """
    try:
        with open(plot_path) as f:
            header = ""
            first_time = None

            for line in f:
                if line.startswith("#"):
                    header = line.strip("#").strip()
                    continue

                if not line.strip():
                    continue

                parts = [p.strip() for p in line.split(",")]

                if not header:
                    return "-"

                header_cols = [h.strip() for h in header.split(",")]

                # Detect format
                if "relative_time" in header_cols:
                    time_value = float(parts[0])
                    crash_col = header_cols.index("saved_crashes")
                    hang_col = header_cols.index("saved_hangs")

                elif "unix_time" in header_cols:
                    current_t = float(parts[0])
                    if first_time is None:
                        first_time = current_t

                    time_value = (current_t - first_time) + 60

                    crash_col = header_cols.index("unique_crashes")
                    hang_col = header_cols.index("unique_hangs")
                else:
                    return "-"

                event_col = crash_col if event_type == "crash" else hang_col

                try:
                    saved_value = int(float(parts[event_col]))
                except Exception:
                    continue

                if saved_value > 0:
                    return format_time(time_value)

    except Exception:
        pass

    return "-"


# -------------------- Derived metrics --------------------

def derive_metrics(data: dict) -> dict:
    """
    Computes derived and formatted metrics from raw fuzzer data.
    """
    derived = {}

    try:
        execs_done = clean_float(data.get("total_execs", 0))
        execs_per_sec = clean_float(data.get("execs_per_sec", 0))
        crashes = clean_float(data.get("saved_crashes", 0))
        hangs = clean_float(data.get("saved_hangs", 0))
        map_size = clean_float(data.get("map_size", 0))
        corpus = clean_float(data.get("corpus_count", 1))

        # Coverage ratio (based on bitmap size)
        derived["coverage_ratio"] = f"{map_size:.2f}%" if map_size else "-"

        # Crashes per hour
        run_time = clean_float(data.get("run_time", 0))
        if run_time == 0:
            run_time = clean_float(data.get("uptime", 0))

        hours = run_time / 3600 if run_time else 0
        derived["crashes_per_hour"] = f"{(crashes / hours):.2f}" if hours > 0 else "-"

        # Executions per input
        derived["execs_per_input"] = f"{(execs_done / corpus):.2f}" if corpus > 0 else "-"

        # Uptime (fallback handling for AFLGo/EcoFuzz)
        try:
            uptime_val = clean_float(data.get("run_time", data.get("uptime", 0)))

            if uptime_val == 0:
                start_t = clean_float(data.get("start_time", 0))
                last_t = clean_float(data.get("last_update", 0))
                if last_t > start_t > 0:
                    uptime_val = last_t - start_t

            derived["uptime"] = format_time(uptime_val)
        except Exception:
            derived["uptime"] = "-"

        # Base metrics
        for field in [
            "execs_per_sec", "total_execs", "saved_crashes", "saved_hangs",
            "corpus_count", "map_size", "edges_found"
        ]:
            val = data.get(field, "-")
            derived[field] = val if val != "" else "-"

        # Additional metrics (pass-through)
        for extra in ["stability", "max_depth", "pending_total", "pending_favs"]:
            derived[extra] = data.get(extra, "-")

    except Exception:
        pass

    return derived


# -------------------- Main parsing --------------------

def parse_fuzzer_stats(path: Path) -> dict:
    """
    Parses and normalizes a fuzzer_stats file.
    """
    data = {}

    try:
        with open(path) as f:
            for line in f:
                if not line.strip() or ":" not in line:
                    continue
                key, val = line.split(":", 1)
                data[key.strip()] = val.strip()
    except Exception:
        return {}

    # Normalize keys
    data = normalize_metrics(data)

    # Compute derived metrics
    derived = derive_metrics(data)

    # Extract time-to-first events from plot_data
    plot_file = path.parent / "plot_data"

    if plot_file.exists():
        derived["time_to_first_crash"] = get_time_to_first_event_from_plot(plot_file, "crash")
        derived["time_to_first_hang"] = get_time_to_first_event_from_plot(plot_file, "hang")
    else:
        derived["time_to_first_crash"] = "-"
        derived["time_to_first_hang"] = "-"

    return derived


# -------------------- Coverage parsing --------------------

def parse_cov_info(cov_path: Path) -> dict:
    """
    Parses cov_info.json produced by observer_cov.py.

    Returns formatted coverage metrics.
    """
    if not cov_path.exists():
        return {}

    try:
        obj = json.loads(cov_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    out = {}

    # Percent metrics
    out["cov_branches_percent"] = f"{obj.get('branches_percent', '-'):.2f}%" if obj.get('branches_percent') not in ["-", None] else "-"
    out["cov_functions_percent"] = f"{obj.get('functions_percent', '-'):.2f}%" if obj.get('functions_percent') not in ["-", None] else "-"
    out["cov_instantiations_percent"] = f"{obj.get('instantiations_percent', '-'):.2f}%" if obj.get('instantiations_percent') not in ["-", None] else "-"
    out["cov_lines_percent"] = f"{obj.get('lines_percent', '-'):.2f}%" if obj.get('lines_percent') not in ["-", None] else "-"
    out["cov_mcdc_percent"] = f"{obj.get('mcdc_percent', '-'):.2f}%" if obj.get('mcdc_percent') not in ["-", None] else "-"
    out["cov_regions_percent"] = f"{obj.get('regions_percent', '-'):.2f}%" if obj.get('regions_percent') not in ["-", None] else "-"

    # Covered counts
    out["cov_branches_covered"] = obj.get("branches_covered", "-")
    out["cov_functions_covered"] = obj.get("functions_covered", "-")
    out["cov_instantiations_covered"] = obj.get("instantiations_covered", "-")
    out["cov_lines_covered"] = obj.get("lines_covered", "-")
    out["cov_mcdc_covered"] = obj.get("mcdc_covered", "-")
    out["cov_regions_covered"] = obj.get("regions_covered", "-")

    return out


# -------------------- Entry point --------------------

def get_latest_metrics(program: str, mode: str) -> dict:
    """
    Reads all fuzzer_stats files for a given program and mode (GrayBox/BlackBox).

    Supports directory structure:
        results/<program>/<fuzzer>/<variant>[/<worker?>]/fuzzer_stats
    """
    results = {}
    base_dir = Path(f"results/{program}")

    if not base_dir.exists():
        print(f"[DEBUG] No results found for {program}")
        return results

    # Recursively search all fuzzer_stats files
    for stats_file in base_dir.rglob("fuzzer_stats"):
        parent = stats_file.parent

        worker_like = parent.name.startswith("fuzzer")

        if worker_like:
            fuzzer_name = parent.parent.name
        else:
            fuzzer_name = parent.name

        # QEMU filtering
        if mode == "BlackBox" and "-qemu" not in fuzzer_name:
            continue
        if mode == "GrayBox" and "-qemu" in fuzzer_name:
            continue

        data = parse_fuzzer_stats(stats_file)

        if data:
            # Look for coverage file
            cov_path = parent / "cov_info.json"

            # Fallback: check parent directory
            if not cov_path.exists():
                cov_path = parent.parent / "cov_info.json"

            # Merge coverage metrics
            cov_metrics = parse_cov_info(cov_path)
            data.update(cov_metrics)

            results[fuzzer_name] = data

    return results