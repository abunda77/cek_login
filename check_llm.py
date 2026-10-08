#!/usr/bin/env python3
"""Smoke test: does the LLM analysis in cek_login.py work with the .env config?

This script reads the provider configuration from an env file (default ``.env``),
feeds a small, deterministic set of synthetic SSH evidence through the same
pipeline the CLI uses, and asks the configured LLM to correlate it. It then
validates the returned ``LLMReport`` object.

Usage:
    python test_llm.py                 # full test: call the configured LLM
    python test_llm.py --dry-run       # config + pipeline only, no network call
    python test_llm.py --env-file .env.example
    python check_llm.py --json          # print the raw LLM report as JSON
    python test_llm.py --verbose       # traceback on failure

Exit codes:
    0  configuration looks good and (unless --dry-run) the LLM call succeeded
    1  configuration is incomplete or the LLM call/validation failed
    2  missing dependency

This file is named ``check_llm.py`` (not ``test_*.py``) so it is never picked
up by ``python -m unittest discover``. It makes a real (billable) network call
unless ``--dry-run`` is passed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import cek_login
    from cek_login import (
        CollectorResult,
        Config,
        LLMAnalyzer,
        LLMReport,
        SEVERITIES,
        build_findings,
        deterministic_severity,
        llm_payload,
        parse_collectors,
        risk_score,
    )
except ImportError as exc:  # pragma: no cover - dependency guard
    print(f"Missing dependency or import error: {exc}", file=sys.stderr)
    print("Run: pip install openai python-dotenv pydantic rich", file=sys.stderr)
    raise SystemExit(2) from exc

GREEN = "\x1b[32m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
DIM = "\x1b[2m"
RESET = "\x1b[0m"

# Synthetic auth.log evidence: repeated root failures from one IP, then a
# successful root login from the same IP (should trigger R001/R004/R006).
SYNTHETIC_AUTH_LOG = "\n".join(
    [
        "Jan 10 12:00:01 host sshd[100]: Failed password for root from 203.0.113.10 port 51001 ssh2",
        "Jan 10 12:00:03 host sshd[100]: Failed password for root from 203.0.113.10 port 51002 ssh2",
        "Jan 10 12:00:05 host sshd[100]: Failed password for root from 203.0.113.10 port 51003 ssh2",
        "Jan 10 12:00:07 host sshd[100]: Failed password for root from 203.0.113.10 port 51004 ssh2",
        "Jan 10 12:00:09 host sshd[100]: Failed password for root from 203.0.113.10 port 51005 ssh2",
        "Jan 10 12:00:11 host sshd[100]: Failed password for root from 203.0.113.10 port 51006 ssh2",
        "Jan 10 12:00:15 host sshd[101]: Accepted password for root from 203.0.113.10 port 51007 ssh2",
        "Jan 10 12:01:00 host sshd[102]: Failed password for invalid user admin from 198.51.100.7 port 51100 ssh2",
        "Jan 10 12:01:02 host sshd[102]: Failed password for invalid user admin from 198.51.100.7 port 51101 ssh2",
    ]
) + "\n"


def color(enabled: bool, code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def redact(secret: str) -> str:
    if not secret:
        return "<empty>"
    if len(secret) <= 10:
        return "<set: masked>"
    return f"{secret[:6]}...{secret[-4:]} (len={len(secret)})"


def check(label: str, ok: bool, detail: str = "") -> bool:
    mark = "[PASS]" if ok else "[FAIL]"
    line = f"  {mark} {label}"
    if detail:
        line += f" {DIM}{detail}{RESET}"
    print(line)
    return ok


def build_synthetic_evidence() -> tuple[list, list]:
    """Return (events, collectors) built from SYNTHETIC_AUTH_LOG.

    Reuses the real parsers so the test exercises cek_login's pipeline, not a
    parallel reimplementation.
    """
    result = CollectorResult(
        collector="auth_log",
        command=["<synthetic>"],
        status="success",
        exit_code=0,
        stdout=SYNTHETIC_AUTH_LOG,
        stderr="",
        duration_ms=0,
        collected_at=cek_login.now_local().isoformat(),
        metadata={"synthetic": True},
    )
    collectors = [result]
    events = parse_collectors(collectors)
    return events, collectors


def print_config_summary(config: Config, use_color: bool) -> None:
    print("Resolved configuration:")
    rows = [
        ("LLM_PROVIDER / provider", config.provider or "<empty>"),
        ("LLM_BASE_URL / base_url", config.base_url or "<empty>"),
        ("LLM_MODEL / model", config.model or "<empty>"),
        ("LLM_API_KEY / api_key", redact(config.api_key)),
        ("LLM_TIMEOUT / llm_timeout", f"{config.llm_timeout}s"),
        ("LLM_TEMPERATURE / llm_temperature", str(config.llm_temperature)),
    ]
    for label, value in rows:
        print(f"  {label:<32}: {value}")
    # Surface which env names were actually used, so alias mix-ups are obvious.
    used_key_name = "LLM_API_KEY" if os.getenv("LLM_API_KEY") else ("OPENAI_API_KEY" if os.getenv("OPENAI_API_KEY") else "<none>")
    used_url_name = "LLM_BASE_URL" if os.getenv("LLM_BASE_URL") else ("OPENAI_BASE_URL" if os.getenv("OPENAI_BASE_URL") else "<default>")
    print(f"  env source keys                 : api_key={used_key_name}, base_url={used_url_name}")
    if not config.provider or config.provider == "openai":
        print(f"  {color(use_color, YELLOW, 'note')}: provider defaults to openai when LLM_PROVIDER is unset.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke test the cek_login.py LLM integration using an env file.")
    parser.add_argument("--env-file", default=".env", help="Env file to load before reading config (default: .env).")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and pipeline only; do not call the LLM.")
    parser.add_argument("--json", action="store_true", help="Print the LLM report as JSON.")
    parser.add_argument("--verbose", action="store_true", help="Print tracebacks on failure.")
    parser.add_argument("--llm-timeout", type=int, help="Override the LLM request timeout in seconds.")
    args = parser.parse_args(argv)

    use_color = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    failures: list[str] = []

    # ---- 1. Load the env file, then read Config the same way the CLI does ----
    env_path = Path(args.env_file)
    if env_path.is_file():
        cek_login.load_dotenv(env_path)
        print(f"Loaded env file: {env_path} ({DIM}{env_path.resolve()}{RESET})")
    else:
        print(color(use_color, YELLOW, f"Env file not found: {env_path}") + " (falling back to the process environment)")

    config = Config.from_env()
    if args.llm_timeout is not None:
        config.llm_timeout = args.llm_timeout
    print_config_summary(config, use_color)

    print("\nConfiguration checks:")
    if not check("LLM_MODEL is set", bool(config.model)):
        failures.append("LLM_MODEL is not set")
    if not check("LLM_API_KEY is set", bool(config.api_key)):
        failures.append("LLM_API_KEY is not set")
    if not check("LLM_BASE_URL is set", bool(config.base_url)):
        failures.append("LLM_BASE_URL is not set")
    print(f"  [INFO] provider = {config.provider or '<empty>'}")

    # ---- 2. Exercise the deterministic pipeline with synthetic evidence ----
    print("\nDeterministic pipeline (synthetic evidence):")
    events, collectors = build_synthetic_evidence()
    findings = build_findings(events)
    score = risk_score(findings)
    det_sev = deterministic_severity(findings, events)
    print(f"  events={len(events)} findings={len(findings)} score={score} severity={det_sev}")
    for finding in findings:
        print(f"    - [{finding.severity}] {finding.rule_id} {finding.title}")
    if not check("pipeline produced events", len(events) >= 7, f"{len(events)} events"):
        failures.append("pipeline produced no/few events")
    if not check("pipeline produced findings", bool(findings), f"{len(findings)} findings"):
        failures.append("pipeline produced no findings")

    if failures:
        print("\n" + color(use_color, RED, "CONFIG FAILED:") + " " + "; ".join(failures))
        print("Fix the env file (see .env.example) and re-run.")
        return 1

    # ---- 3. Inspect the prompt that would be sent (no network) ----
    prompt = llm_payload(events, collectors, findings, score, det_sev)
    print("\nPrompt sanity checks:")
    check("prompt contains UNTRUSTED_LOG_DATA marker", "UNTRUSTED_LOG_DATA" in prompt)
    check("prompt requests JSON schema fields", all(k in prompt for k in ("severity", "confidence", "recommendations")))
    print(f"  {DIM}prompt size: {len(prompt)} chars{RESET}")

    if args.dry_run:
        print("\n" + color(use_color, GREEN, "DRY RUN OK:") + " config + pipeline are valid; LLM call skipped.")
        return 0

    # ---- 4. Real end-to-end LLM call through LLMAnalyzer ----
    print(f"\nCalling {config.provider} via {config.base_url} model={config.model} ...")
    started = time.monotonic()
    try:
        report = LLMAnalyzer(config).analyze(events, collectors, findings, score, det_sev)
    except Exception as exc:  # noqa: BLE001 - surface any provider/network error
        elapsed = time.monotonic() - started
        print(color(use_color, RED, f"LLM CALL FAILED after {elapsed:.1f}s: {exc}"))
        if args.verbose:
            import traceback

            traceback.print_exc()
        print("\nTroubleshooting:")
        print("  - Check LLM_API_KEY, LLM_BASE_URL and LLM_MODEL in .env (compare with .env.example).")
        print("  - Confirm the provider/model name is valid for your account and region.")
        print("  - For local servers (ollama, lm-studio) ensure the server is running.")
        return 1
    elapsed = time.monotonic() - started
    print(color(use_color, GREEN, f"LLM responded in {elapsed:.1f}s."))

    # ---- 5. Validate the returned report ----
    print("\nResponse checks:")
    ok = True
    ok &= check("returned an LLMReport instance", isinstance(report, LLMReport), type(report).__name__)
    ok &= check("severity is valid", report.severity in SEVERITIES, report.severity)
    ok &= check("confidence in [0, 1]", 0.0 <= report.confidence <= 1.0, str(report.confidence))
    ok &= check("summary is non-empty", bool(report.summary.strip()), f"{len(report.summary)} chars")
    ok &= check("conclusion is non-empty", bool(report.conclusion.strip()), f"{len(report.conclusion)} chars")
    ok &= check("recommendations is a list", isinstance(report.recommendations, list), f"{len(report.recommendations)} items")

    if args.json:
        print("\n--- LLM report (JSON) ---")
        print(json.dumps(report.model_dump(), ensure_ascii=False, indent=2))
    else:
        print("\n--- LLM report ---")
        print(f"  severity       : {report.severity}")
        print(f"  confidence     : {report.confidence:.0%}")
        print(f"  summary        : {report.summary}")
        if report.findings:
            print(f"  findings       : {len(report.findings)}")
            for finding in report.findings:
                print(f"    - [{finding.severity}] {finding.title}")
        if report.correlations:
            print(f"  correlations   : {len(report.correlations)}")
        if report.recommendations:
            print(f"  recommendations: {len(report.recommendations)}")
            for rec in report.recommendations[:5]:
                print(f"    {rec.priority}. {rec.action}")
        print(f"  conclusion     : {report.conclusion}")

    if not ok:
        print("\n" + color(use_color, RED, "VALIDATION FAILED:") + " the LLM responded but the report was invalid.")
        return 1

    print("\n" + color(use_color, GREEN, "OK:") + " LLM analysis works with the loaded env configuration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
