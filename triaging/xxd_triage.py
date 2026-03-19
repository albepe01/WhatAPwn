#!/usr/bin/env python3
import subprocess
import argparse
import os
import re

def classify_word(word: str):
    """
    A word is a 4 hex digit (two bytes, standard xxd format).
    The color is decided by the two bytes.
    """
    if not re.fullmatch(r"[0-9a-fA-F]{4}", word):
        return word  # fallback

    b1 = int(word[0:2], 16)
    b2 = int(word[2:4], 16)
    bytes_vals = [b1, b2]
    chars = [chr(b) for b in bytes_vals]

    if all(0x20 <= b <= 0x7E for b in bytes_vals):
        if all(c.isdigit() for c in chars):
            # Digits: green
            return f"[green]{word}[/]"
        if all(c.isalpha() for c in chars):
            # Letters: cyan
            return f"[cyan]{word}[/]"
        # Mixed printable: keep neutral
        return word

    # Any byte outside the printable range: red
    if any(b < 0x20 or b > 0x7F for b in bytes_vals):
        return f"[red]{word}[/]"

    return word


OFFSET_FMT = "[magenta]{}[/]"

def colorize_xxd_line(line: str) -> str:
    """
    Colorizes a single line of xxd, example:
    00000030: 3131 3131 3131 0d03  11111111..
    """

    # Match the offset
    m = re.match(r"^([0-9a-fA-F]{8}):\s*(.*)$", line)
    if not m:
        return line

    offset = m.group(1)
    rest = m.group(2)

    if not rest:
        return OFFSET_FMT.format(offset) + ":"

    # If there's a double space, split the hex and ascii parts
    if "  " in rest:
        hex_part, ascii_part = rest.split("  ", 1)
    else:
        hex_part, ascii_part = rest, ""

    # Color the hex words (4 hex = 2 byte)
    hex_words = hex_part.split()
    colored_words = [classify_word(w) for w in hex_words]
    hex_colored = " ".join(colored_words)

    ascii_colored = ascii_part 

    if ascii_part:
        return f"{OFFSET_FMT.format(offset)}: {hex_colored}  {ascii_colored}"
    else:
        return f"{OFFSET_FMT.format(offset)}: {hex_colored}"


def escape_non_color_tags(s: str) -> str:
    """
    Escapes sequences like [/something] that are not color tags.
    """
    allowed = {"", "red", "green", "cyan", "magenta"}

    def repl(m):
        tag = m.group(1)
        if tag in allowed:
            return f"[/{tag}]"
        return f"\\[/{tag}\\]"

    # Only closing tags
    s = re.sub(r"\[/([^\]]+)\]", repl, s)
    return s


def run_xxd(crash_path: str, out_dir: str):
    """
    Executes xxd and colorizes the output.
    """
    os.makedirs(out_dir, exist_ok=True)

    base = os.path.basename(crash_path).replace(":", "_")
    log_path = os.path.join(out_dir, f"xxd_{base}.log")

    result = subprocess.run(
        ["xxd", crash_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "TERM": "xterm-256color"},
    )

    raw = result.stdout

    pretty_lines = []
    for line in raw.splitlines():
        colored = colorize_xxd_line(line)
        safe = escape_non_color_tags(colored)
        pretty_lines.append(safe)

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(pretty_lines))

    print("[OK] XXD triage completato.")
    print(" → Log :", log_path)


if __name__ == "__main__":
    """
    CLI for the XXD triage script.
    """
    parser = argparse.ArgumentParser(description="XXD triage script")
    parser.add_argument("--crash", required=True, help="Crash file")
    parser.add_argument("--out", required=True, help="Output directory")

    args = parser.parse_args()

    if not os.path.isfile(args.crash):
        print("[ERRORE] Crash file non trovato:", args.crash)
        exit(1)

    run_xxd(args.crash, args.out)
