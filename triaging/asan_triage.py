#!/usr/bin/env python3
import subprocess
import argparse
import os
import json
import re
import textwrap

# ANSI → TEXTUAL MARKUP (STATEFUL, SAFE, NO MARKUPERROR)

ANSI_PATTERN = re.compile(r"\x1b\[([0-9;]*)m")

SGR_MAP = {
    "1": "[bold]",
    "4": "[underline]",

    # Normal colors
    "30": "[black]", "31": "[red]", "32": "[green]", "33": "[yellow]",
    "34": "[blue]", "35": "[magenta]", "36": "[cyan]", "37": "[white]",

    # Bright colors
    "90": "[bright_black]", "91": "[bright_red]", "92": "[bright_green]",
    "93": "[bright_yellow]", "94": "[bright_blue]", "95": "[bright_magenta]",
    "96": "[bright_cyan]", "97": "[bright_white]",

    # Backgrounds
    "40": "[on_black]", "41": "[on_red]", "42": "[on_green]",
    "43": "[on_yellow]", "44": "[on_blue]", "45": "[on_magenta]",
    "46": "[on_cyan]", "47": "[on_white]",

    # Bright backgrounds
    "100": "[on_bright_black]", "101": "[on_bright_red]",
    "102": "[on_bright_green]", "103": "[on_bright_yellow]",
    "104": "[on_bright_blue]", "105": "[on_bright_magenta]",
    "106": "[on_bright_cyan]", "107": "[on_bright_white]",
}

def ansi_to_markup(text: str) -> str:
    """
    Converts ANSI escape sequences to markup.
    """
    out = []
    i = 0
    n = len(text)
    style_active = False

    while i < n:
        ch = text[i]

        if ch == "\x1b":  # ANSI sequence
            m = ANSI_PATTERN.match(text, i)
            if not m:
                out.append(ch)
                i += 1
                continue

            codes = m.group(1)

            if codes == "" or codes == "0":
                if style_active:
                    out.append("[/]")
                    style_active = False
            else:
                tags = []
                for part in codes.split(";"):
                    tag = SGR_MAP.get(part)
                    if tag:
                        tags.append(tag)

                if tags:
                    out.append("".join(tags))
                    style_active = True

            i = m.end()
            continue

        if ch == "\n":
            if style_active:
                out.append("[/]")
                style_active = False
            out.append("\n")
            i += 1
            continue

        out.append(ch)
        i += 1

    if style_active:
        out.append("[/]")

    return "".join(out)


def wrap_long(value, width=100, indent=4):
    """
    Wraps long text to improve readability.
    """
    if len(value) <= width:
        return value
    return textwrap.fill(
        value,
        width=width,
        subsequent_indent=" " * indent,
        break_long_words=True,
        break_on_hyphens=False
    )


def parse_asan_output(output: str):
    """
    ASAN Output Parser to produce a JSON object.
    """
    data = {
        "error": None, "address": None, "operation": None, "size": None,
        "pc": None, "bp": None, "sp": None,
        "summary": None, "file": None, "line": None, "function": None,
    }

    m = re.search(r"ERROR: AddressSanitizer: ([^\s]+)", output)
    if m:
        data["error"] = m.group(1)

    m = re.search(r"SUMMARY: [^\n]+", output)
    if m:
        data["summary"] = m.group(0)

    m = re.search(r"pc\s*(0x[0-9a-fA-F]+)", output)
    if m:
        data["pc"] = m.group(1)

    m = re.search(r"bp\s*(0x[0-9a-fA-F]+)", output)
    if m:
        data["bp"] = m.group(1)

    m = re.search(r"sp\s*(0x[0-9a-fA-F]+)", output)
    if m:
        data["sp"] = m.group(1)

    m = re.search(r"(READ|WRITE) of size (\d+)", output)
    if m:
        data["operation"] = m.group(1)
        data["size"] = int(m.group(2))

    m = re.search(r"^(.*?):(\d+):(\d+)", output, re.MULTILINE)
    if m:
        data["file"] = m.group(1)
        data["line"] = int(m.group(2))

    m = re.search(r"at (0x[0-9a-fA-F]+)", output)
    if m:
        data["address"] = m.group(1)

    return data


def run_asan_triage(bin_path: str, crash_path: str, logs_dir: str, file_mode: bool = False):
    """
    Main triage script. Launches a container with ASAN and parses the output.
    """
    os.makedirs(logs_dir, exist_ok=True)

    base_name = os.path.basename(crash_path).replace(":", "_")
    log_path = os.path.join(logs_dir, f"asan_{base_name}.log")
    json_path = os.path.join(logs_dir, f"asan_{base_name}.json")

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "color=always"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"

    # Constructs the command
    if file_mode:
        # ./bin crash
        cmd = [bin_path, crash_path]
        stdin = None
        crash_input = None
    else:
        # ./bin < crash
        cmd = [bin_path]
        crash_input = open(crash_path, "rb")
        stdin = crash_input

    try:
        result = subprocess.run(
            cmd,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            env=env,
        )
    finally:
        if not file_mode and crash_input is not None:
            crash_input.close()

    asan_raw = result.stdout.decode("latin-1")

    # Wrapping + ANSI → MARKUP

    pretty_lines = []

    for raw_line in asan_raw.splitlines():
        wrapped = wrap_long(raw_line)

        for part in wrapped.split("\n"):
            # Keep original indentation
            stripped = part.lstrip()
            indent = len(part) - len(stripped)
            prefix = " " * indent
            pretty = ansi_to_markup(stripped)
            pretty_lines.append(prefix + pretty)

    with open(log_path, "w", encoding="utf-8") as lf:
        lf.write("\n".join(pretty_lines))

    parsed = parse_asan_output(asan_raw)
    parsed["bin"] = bin_path
    parsed["crash"] = crash_path
    parsed["exit_code"] = result.returncode
    parsed["input_mode"] = "file" if file_mode else "stdin"

    with open(json_path, "w") as jf:
        json.dump(parsed, jf, indent=4)

    print("[OK] ASAN triage completed.")
    print(" → Log :", log_path)
    print(" → JSON:", json_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ASAN triage script")

    parser.add_argument("bin", nargs="?", help="ASAN binary (positional or --bin)")
    parser.add_argument("crash", nargs="?", help="Crash file (positional or --crash)")

    parser.add_argument("--bin", dest="bin_flag", help="ASAN binary")
    parser.add_argument("--crash", dest="crash_flag", help="Crash file")
    parser.add_argument("--logs", required=True, help="Output directory for logs/json")
    parser.add_argument(
        "--file",
        action="store_true",
        help="Using the crash as argument instead of stdin (./bin crash) instead of stdin (./bin < crash)",
    )

    args = parser.parse_args()

    bin_path = args.bin_flag or args.bin
    crash_path = args.crash_flag or args.crash

    if not bin_path or not crash_path:
        print("ERROR: you must supply BIN and CRASH (positional or via --bin/--crash)")
        exit(1)

    run_asan_triage(bin_path, crash_path, args.logs, file_mode=args.file)
