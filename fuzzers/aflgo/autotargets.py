#!/usr/bin/env python3
import argparse
import os
import re
from pathlib import Path


# Regex matching potentially dangerous "sink" functions
# Includes memory operations, I/O, string functions, and exec-related calls
SINK_RE = re.compile(
    r"\b("
    r"read|recv|recvfrom|"
    r"gets|fgets|"
    r"strcpy|strncpy|strcat|strncat|"
    r"memcpy|memmove|"
    r"printf|sprintf|snprintf|vsprintf|vsnprintf|"
    r"scanf|sscanf|fscanf|"
    r"system|popen|execve|execl|execv|execlp|execvp|"
    r"free"
    r")\s*\("
)

# Control-flow keywords used to exclude non-function definitions
CTRL_KEYWORDS = ("if", "for", "while", "switch", "return", "sizeof")


def strip_comments_and_strings(line):
    """
    Removes comments and string literals from a line of C code.

    This helps avoid false positives when searching for sinks.
    """
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    return line


def find_sink_lines(src_text):
    """
    Returns line numbers containing sink functions.
    """
    out = []
    for i, raw in enumerate(src_text.splitlines(), start=1):
        line = strip_comments_and_strings(raw)
        if SINK_RE.search(line):
            out.append(i)
    return out


def looks_like_func_def(lines, idx):
    """
    Heuristic detection of function definitions.

    Filters out:
        - attributes / asm
        - control statements
        - function prototypes
    Requires '{' either on same line or next non-empty line.
    """
    raw = lines[idx]
    l = strip_comments_and_strings(raw).strip()

    if not l:
        return None

    if "__attribute__" in l or "__asm__" in l:
        return None

    if "(" not in l or ")" not in l:
        return None
    if l.endswith(";"):
        return None

    for k in CTRL_KEYWORDS:
        if l.startswith(k + "(") or l.startswith(k + " ("):
            return None

    has_brace = ("{" in l)
    if not has_brace:
        j = idx + 1
        while j < len(lines):
            nxt = strip_comments_and_strings(lines[j]).strip()
            if nxt == "":
                j += 1
                continue
            has_brace = ("{" in nxt)
            break
        if not has_brace:
            return None

    # Extract function name
    before_paren = l.split("(", 1)[0].rstrip()
    before_paren = re.sub(r"[\s\*]+$", "", before_paren)
    toks = re.split(r"[\s\*]+", before_paren)
    cand = toks[-1] if toks else ""

    if re.match(r"^[A-Za-z_]\w*$", cand):
        return cand

    return None


def find_enclosing_function(src_text, line_no):
    """
    Returns the function name enclosing a given line number.
    """
    lines = src_text.splitlines()
    func = None

    for idx in range(min(line_no, len(lines))):
        name = looks_like_func_def(lines, idx)
        if name:
            func = name

    return func


def file_contains_main(src_text):
    """
    Checks if the source contains a main() function.
    """
    return re.search(r"^\s*.*\bmain\s*\(", src_text, flags=re.M) is not None


def read_text(path):
    """Reads a file as UTF-8 with fallback handling."""
    return path.read_text(encoding="utf-8", errors="replace")


def write_lines(path, lines):
    """Writes a list of lines to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(str(path), "w") as f:
        for l in lines:
            f.write(l if l.endswith("\n") else l + "\n")


def main():
    """
    Entry point for automatic AFLGo target extraction.

    Generates:
        - BBcandidates.txt
        - BBtargets.txt
        - Ftargets.txt
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("tmp_dir", nargs="?", default="/workspace/aflgo_temp")
    ap.add_argument("--top-k", type=int, default=0,
                    help="If >0, keep only the first K sink occurrences")

    args = ap.parse_args()

    src_path = Path(args.src)
    tmp_dir = Path(args.tmp_dir)

    print("[autotargets.py] PWD:", os.getcwd())
    print("[autotargets.py] SRC:", src_path)

    try:
        src_path.stat()
    except Exception:
        print("[autotargets.py] ERROR: SRC does not exist")

        tmp_dir.mkdir(parents=True, exist_ok=True)
        write_lines(tmp_dir / "Ftargets.txt", ["main"])
        write_lines(tmp_dir / "BBtargets.txt", [])

        return 0

    text = read_text(src_path)
    base = src_path.name

    sink_lines = find_sink_lines(text)

    if args.top_k and args.top_k > 0:
        sink_lines = sink_lines[: args.top_k]

    print("[autotargets.py] sink lines:", sink_lines if sink_lines else "NONE")

    # BB candidates (one per sink line)
    bb_candidates = [f"{base}:{ln}:" for ln in sink_lines]
    write_lines(tmp_dir / "BBcandidates.txt", bb_candidates)

    # Extract enclosing functions
    ftargets = []
    seen = set()

    for ln in sink_lines:
        func = find_enclosing_function(text, ln)
        if func and func not in seen:
            seen.add(func)
            ftargets.append(func)

    # Fallback
    if not ftargets:
        ftargets = ["main"] if file_contains_main(text) else ["main"]

    write_lines(tmp_dir / "Ftargets.txt", ftargets)

    # Filter BBtargets using BBnames if available
    bbnames_path = tmp_dir / "BBnames.txt"

    if bbnames_path.exists() and bb_candidates:
        bbnames = set(read_text(bbnames_path).splitlines())
        bbtargets = [x for x in bb_candidates if x in bbnames]
    else:
        bbtargets = list(bb_candidates)

    write_lines(tmp_dir / "BBtargets.txt", bbtargets)

    print("[autotargets.py] Ftargets:", ftargets)

    return 0


if __name__ == "__main__":
    main()