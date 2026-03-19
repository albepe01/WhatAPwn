from pathlib import Path
from dashboard.utils.fuzzer_stats_reader import get_latest_metrics

# Root directory containing benchmark programs
RESULTS_DIR = Path("benchmarks")


def get_available_programs():
    """
    Returns a sorted list of available programs.

    A program is considered available if it corresponds to a directory
    inside the RESULTS_DIR.
    """
    if not RESULTS_DIR.exists():
        return []

    return sorted([d.name for d in RESULTS_DIR.iterdir() if d.is_dir()])


def get_fuzzer_columns(program: str, mode: str):
    """
    Retrieves the active fuzzers for a given program and execution mode.

    This function uses the keys returned by get_latest_metrics(program, mode),
    ensuring that column names always match the actual data source.

    Returns:
        List of fuzzer names (used as table columns).
    """
    metrics_by_fuzzer = get_latest_metrics(program, mode)
    return list(metrics_by_fuzzer.keys())