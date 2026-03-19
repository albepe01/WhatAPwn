#!/usr/bin/env python3
import subprocess
import argparse
import os
import json
import re
import tempfile
import shutil
import textwrap
import uuid
import threading
from pathlib import Path


# ANSI → TEXTUAL MARKUP (STATEFUL, SAFE, NO MARKUPERROR)

ANSI_PATTERN = re.compile(r"\x1b\[([0-9;]*)m")

SGR_MAP = {
    "1": "[bold]",
    "4": "[underline]",
    "30": "[black]", "31": "[red]", "32": "[green]", "33": "[yellow]",
    "34": "[blue]", "35": "[magenta]", "36": "[cyan]", "37": "[white]",
    "90": "[bright_black]", "91": "[bright_red]", "92": "[bright_green]",
    "93": "[bright_yellow]", "94": "[bright_blue]", "95": "[bright_magenta]",
    "96": "[bright_cyan]", "97": "[bright_white]",
    "40": "[on_black]", "41": "[on_red]", "42": "[on_green]",
    "43": "[on_yellow]", "44": "[on_blue]", "45": "[on_magenta]",
    "46": "[on_cyan]", "47": "[on_white]",
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
        if ch == "\x1b":
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
                for c in codes.split(";"):
                    tag = SGR_MAP.get(c)
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


def wrap_long(value, width=300, indent=4):
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
        break_on_hyphens=False,
    )


def parse_qasan_output(text):
    """
    QASAN output parser that produces a JSON object.
    """
    result = {
        "error": None, "address": None, "operation": None, "size": None,
        "pc": None, "bp": None, "sp": None,
        "summary": None, "file": None, "line": None, "function": None,
    }

    m = re.search(r"ERROR: QEMU-AddressSanitizer: ([^\s]+)", text)
    if m:
        result["error"] = m.group(1)

    m = re.search(r"on address (\S+)", text)
    if m:
        result["address"] = m.group(1)

    m = re.search(r"(READ|WRITE) of size (\d+)", text)
    if m:
        result["operation"] = m.group(1)
        result["size"] = int(m.group(2))

    m = re.search(r"pc (\S+) bp (\S+) sp (\S+)", text)
    if m:
        result["pc"] = m.group(1)
        result["bp"] = m.group(2)
        result["sp"] = m.group(3)

    m = re.search(r"SUMMARY: QEMU-AddressSanitizer: ([^\n]+)", text)
    if m:
        result["summary"] = m.group(1).strip()

    m = re.search(r"#0\s+0x[0-9a-fA-F]+\s+in ([^\s]+)", text)
    if m:
        result["function"] = m.group(1)

    m = re.search(r"in (.*):(\d+):\d+", text)
    if m:
        result["file"] = m.group(1)
        result["line"] = int(m.group(2))

    return result


def run_cmd(cmd, *, check=False, capture_output=False, text=True):
    """Small subprocess wrapper for Docker commands."""
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=text,
    )


def ensure_qasan_image(image_tag: str = "qasan:latest") -> Path:
    """
    Ensures the QASAN image exists locally.

    If the image is missing, it is built automatically from:
        ./qasan/Dockerfile
    where "./" is resolved relative to this script location.
    """
    try:
        run_cmd(["docker", "image", "inspect", image_tag], check=True, capture_output=True)
        print(f"[+] Found local Docker image: {image_tag}")
    except subprocess.CalledProcessError:
        script_dir = Path(__file__).resolve().parent
        qasan_dir = script_dir / "qasan"
        dockerfile = qasan_dir / "Dockerfile"

        if not dockerfile.is_file():
            raise FileNotFoundError(
                f"QASAN Dockerfile not found at: {dockerfile}"
            )

        print(f"[+] Docker image '{image_tag}' not found locally.")
        print(f"[+] Building it from: {dockerfile}")
        run_cmd(
            [
                "docker", "build",
                "-t", image_tag,
                "-f", str(dockerfile),
                str(qasan_dir),
            ],
            check=True,
        )
        print(f"[OK] Built Docker image: {image_tag}")

    return Path(__file__).resolve().parent / "qasan" / "Dockerfile"


def main():
    """
    QASAN triager. Launches a container with QASAN and parses the output.
    """
    parser = argparse.ArgumentParser(description="QASAN triager")
    parser.add_argument("--bin", required=True)
    parser.add_argument("--crash", required=True)
    parser.add_argument("--logs", required=True)
    parser.add_argument("--file", action="store_true", help="Use crash file as argument instead of stdin")
    parser.add_argument("--image", default="qasan:latest", help="Docker image tag to use/build")
    args = parser.parse_args()

    bin_path = os.path.abspath(args.bin)
    crash_path = os.path.abspath(args.crash)
    logs_dir = os.path.abspath(args.logs)

    if not os.path.isfile(bin_path):
        print("[ERR] Binary file not found")
        exit(1)
    if not os.path.isfile(crash_path):
        print("[ERR] Crash not found")
        exit(1)
    if not os.path.isdir(logs_dir):
        os.makedirs(logs_dir)

    try:
        ensure_qasan_image(args.image)
    except Exception as e:
        print(f"[ERR] Unable to prepare QASAN image: {e}")
        exit(1)

    base = os.path.basename(crash_path).replace(":", "_")
    log_path = os.path.join(logs_dir, f"qasan_{base}.log")
    json_path = os.path.join(logs_dir, f"qasan_{base}.json")

    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", base)
    container_name = f"qasan_triage_{uuid.uuid4().hex[:8]}"

    container_bin = "/workspace/bin"
    container_crash = "/workspace/crash"

    # Copy crash to a temporary file to avoid path issues inside Docker
    fd, tmp_crash = tempfile.mkstemp(prefix="qasan_crash_", suffix=".bin")
    os.close(fd)
    shutil.copyfile(crash_path, tmp_crash)

    # Build Docker command
    if args.file:
        docker_cmd = [
            "docker", "run", "--rm", "--name", container_name,
            "-v", f"{bin_path}:{container_bin}:ro",
            "-v", f"{tmp_crash}:{container_crash}:ro",
            args.image,
            "/opt/qasan/qasan", container_bin, container_crash,
        ]
        stdin_data = None
    else:
        docker_cmd = [
            "docker", "run", "--rm", "--name", container_name,
            "-i",
            "-v", f"{bin_path}:{container_bin}:ro",
            "-v", f"{tmp_crash}:{container_crash}:ro",
            args.image,
            "/opt/qasan/qasan", container_bin,
        ]
        with open(crash_path, "rb") as f:
            stdin_data = f.read()

    print("[+] Starting QASAN container...")

    process = subprocess.Popen(
        docker_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Send stdin when required
    if stdin_data is not None:
        try:
            process.stdin.write(stdin_data)
        except BrokenPipeError:
            pass
    process.stdin.close()

    buf = bytearray()

    def _reader():
        for chunk in iter(lambda: process.stdout.read(4096), b""):
            buf.extend(chunk)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    timeout = int(os.environ.get("QASAN_TIMEOUT", "2"))

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            process.kill()
        except Exception:
            pass

    t.join(timeout=2)

    raw_output = bytes(buf)
    out = raw_output.decode("latin-1")

    subprocess.run(
        ["docker", "rm", "-f", container_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        os.remove(tmp_crash)
    except OSError:
        pass

    # Wrap + ANSI → markup
    pretty_lines = []
    for raw_line in out.splitlines():
        wrapped = wrap_long(raw_line)
        for part in wrapped.split("\n"):
            stripped = part.lstrip()
            indent = len(part) - len(stripped)
            prefix = " " * indent
            pretty_lines.append(prefix + ansi_to_markup(stripped))

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(pretty_lines))

    parsed = parse_qasan_output(out)
    parsed["bin"] = bin_path
    parsed["crash"] = crash_path
    parsed["mode"] = "file" if args.file else "stdin"
    parsed["image"] = args.image

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(parsed, jf, indent=4)

    print("[OK] QASAN triage completed.")
    print(" → Log :", log_path)
    print(" → JSON:", json_path)


if __name__ == "__main__":
    main()
