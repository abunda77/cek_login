"""Analyze failed SSH authentication attempts in a Linux auth.log file."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

FAILED_PASSWORD_RE = re.compile(r"\bFailed password\b.*?\bfrom\s+([^\s]+)")
THRESHOLD = 5

BOLD = "\033[1m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def extract_failed_ip(line: str) -> str | None:
    """Return the valid IP in a failed SSH password line, if present."""
    match = FAILED_PASSWORD_RE.search(line)
    if not match:
        return None

    candidate = match.group(1)
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def count_failed_attempts(lines: Iterable[str]) -> Counter[str]:
    """Count failed SSH password attempts by source IP."""
    counts: Counter[str] = Counter()
    for line in lines:
        ip = extract_failed_ip(line)
        if ip is not None:
            counts[ip] += 1
    return counts


def find_suspicious_ips(
    counts: Mapping[str, int], threshold: int = THRESHOLD
) -> list[tuple[str, int]]:
    """Return IPs at or above the failure threshold in display order."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    suspicious = [(ip, count) for ip, count in counts.items() if count >= threshold]
    return sorted(suspicious, key=lambda item: (-item[1], item[0]))


def _style(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{RESET}" if color else text


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."


def _boxed_metadata(label: str, value: str, vertical: str) -> str:
    content_width = 62
    prefix = f"  {label} : "
    content = prefix + _fit(value, content_width - len(prefix))
    return vertical + content.ljust(content_width) + vertical


def render_report(
    source: str,
    suspicious_ips: Sequence[tuple[str, int]],
    color: bool = False,
    unicode_output: bool = True,
) -> str:
    """Render a readable terminal report."""
    if unicode_output:
        box = ("╔", "╗", "╠", "╣", "╚", "╝", "═", "┌", "┬", "┐", "│", "├", "┼", "┤", "└", "┴", "┘")
        warning = "⚠"
    else:
        box = ("+", "+", "+", "+", "+", "+", "=", "+", "+", "+", "|", "+", "+", "+", "+", "+", "+")
        warning = "!"

    top_left, top_right, mid_left, mid_right, bottom_left, bottom_right, horizontal, table_left, table_mid, table_right, vertical, row_left, row_mid, row_right, table_bottom_left, table_bottom_mid, table_bottom_right = box
    border = horizontal * 62
    lines = [
        top_left + border + top_right,
        vertical + _style("SSH LOGIN SECURITY ANALYSIS".center(62), BOLD + CYAN, color) + vertical,
        mid_left + border + mid_right,
        _boxed_metadata("Source", source, vertical),
        _boxed_metadata("Rule  ", f"failed authentication attempts >= {THRESHOLD}", vertical),
        bottom_left + border + bottom_right,
        "",
        "  " + _style("SUSPICIOUS IP ADDRESSES", BOLD + YELLOW, color),
    ]

    ip_width = 22
    attempts_width = 16
    lines.append("  " + table_left + horizontal * ip_width + table_mid + horizontal * attempts_width + table_right)
    lines.append(
        "  " + vertical
        + f" {'IP ADDRESS':<{ip_width - 1}}" + vertical
        + f" {'FAILED ATTEMPTS':<{attempts_width - 1}}" + vertical
    )
    lines.append("  " + row_left + horizontal * ip_width + row_mid + horizontal * attempts_width + row_right)

    if suspicious_ips:
        for ip, count in suspicious_ips:
            lines.append(
                "  " + vertical
                + f" {ip:<{ip_width - 1}}" + vertical
                + f" {count:>{attempts_width - 1}}" + vertical
            )
    else:
        lines.append(
            "  " + vertical
            + f" {'No suspicious IPs':<{ip_width - 1}}" + vertical
            + f" {'-':>{attempts_width - 1}}" + vertical
        )

    lines.extend(
        [
            "  " + table_bottom_left + horizontal * ip_width + table_bottom_mid + horizontal * attempts_width + table_bottom_right,
            "",
        ]
    )

    if suspicious_ips:
        count = len(suspicious_ips)
        label = "IP address" if count == 1 else "IP addresses"
        lines.append("  " + _style(f"{warning} {count} {label} exceeded the failure threshold.", YELLOW, color))
    else:
        lines.append("  No suspicious IP addresses found.")

    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze_login.py",
        usage="python analyze_login.py <auth.log>",
        description="Find source IPs with repeated failed SSH authentication attempts.",
    )
    parser.add_argument("logfile", help="path to a Linux/SSH auth.log file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line application and return its exit code."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)

    path = Path(args.__dict__.get("logfile", ""))
    try:
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            counts = count_failed_attempts(log_file)
    except OSError as error:
        print(f"Error: cannot read '{path}': {error}", file=sys.stderr)
        return 1

    suspicious_ips = find_suspicious_ips(counts)
    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    encoding = getattr(sys.stdout, "encoding", "") or ""
    unicode_output = encoding.lower().replace("-", "") in {"utf8", "utf16"}
    print(
        render_report(
            str(path),
            suspicious_ips,
            color=use_color,
            unicode_output=unicode_output,
        ),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
