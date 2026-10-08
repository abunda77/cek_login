# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

CLI tool (`analyze_login.py`) that scans a Linux `auth.log` for source IPs with >= 5 failed SSH password attempts and renders a boxed terminal report. Python 3.10+, **stdlib only — never add third-party dependencies.**

## Commands

```bash
python analyze_login.py /var/log/auth.log   # run the CLI
python -m unittest discover -s tests -v     # run all tests
python -m unittest tests.test_analyze_login -v              # full module
python -m unittest tests.test_analyze_login.CliTests.test_cli_reports_suspicious_ip -v  # single test
```

## Architecture

Single module `analyze_login.py`, no packages. Data flow in `main()`: read file (UTF-8, `errors="replace"` so bad bytes never crash) → `count_failed_attempts()` → `find_suspicious_ips()` → `render_report()` → print.

- `extract_failed_ip(line)` — the regex only *finds* the token after `from` in a `Failed password` line; `ipaddress.ip_address` does the *validation*. So hostnames, malformed IPs, success lines, and non-SSH lines all return `None` and are not counted. Supports IPv4 and IPv6.
- `find_suspicious_ips(counts, threshold=5)` — `THRESHOLD = 5` is inclusive; rejects `threshold < 1` with `ValueError`. Sorted by count descending, then IP ascending (tie-breaker).
- `render_report(source, ips, color, unicode_output)` — box-drawing Unicode table, ASCII fallback when `unicode_output=False`. Called with:
  - `color=True` only when `sys.stdout.isatty()` and `NO_COLOR` not in env
  - `unicode_output=False` when stdout encoding can't encode Unicode (e.g. `cp1252`)
- `main(argv) -> int` — returns exit codes rather than raising: `0` success, `1` unreadable file (concise stderr message, no traceback), `2` usage error (argparse). The `if __name__ == "__main__":` block is the only place `SystemExit` is raised.

## Testing conventions

Tests live in `tests/test_analyze_login.py` using stdlib `unittest`. Public functions (`extract_failed_ip`, `count_failed_attempts`, `find_suspicious_ips`, `render_report`, `main`) are tested directly; CLI behavior is tested by calling `main([...])` with redirected stdio (never subprocess). Key invariants covered: threshold 5-inclusive, malformed-token rejection, IPv6 parsing, no ANSI escapes when color is off, ASCII fallback, invalid UTF-8 bytes.

## Context

Design spec and implementation plan live in `docs/superpowers/` (written in a Creole-like language). The README documents user-facing usage in the same style.