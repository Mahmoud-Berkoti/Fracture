"""Scan orchestration.

Loads the target YAML, builds authenticated sessions, dispatches each
enabled module, then writes JSONL audit output. The HTML report is
delegated to core.reporter (built in step 5); if reporter.write_html_report
is not yet implemented the runner logs and continues.

Module functions are imported lazily inside `_collect_modules` so missing
modules in the attack suite (during incremental step-4 builds) only skip
that one module rather than aborting the scan.
"""
from __future__ import annotations

import time
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import structlog
import yaml

from .models import Finding, ScanResult, TargetConfig
from .session import ScanContext, build_context

log = structlog.get_logger(__name__)


ModuleRunner = Callable[[ScanContext, Any], Awaitable[list[Finding]]]


def load_target_config(path: Path) -> TargetConfig:
    raw = yaml.safe_load(path.read_text())
    return TargetConfig.model_validate(raw)


async def _safe_run_module(
    name: str,
    runner: ModuleRunner,
    ctx: ScanContext,
    config: Any,
) -> list[Finding]:
    log.info("module_start", module=name)
    t0 = time.perf_counter()
    try:
        findings = await runner(ctx, config)
    except Exception as exc:
        log.error(
            "module_crashed",
            module=name,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return [
            Finding(
                module=name,
                severity="info",
                title=f"Module {name} crashed during execution",
                description=(
                    f"The {name} module raised an unhandled exception. This is a "
                    f"scanner reliability issue, not a target finding."
                ),
                remediation="Investigate the scanner logs for the stack trace.",
                evidence={"error": str(exc), "error_type": type(exc).__name__},
            )
        ]
    elapsed = round(time.perf_counter() - t0, 3)
    log.info(
        "module_complete",
        module=name,
        finding_count=len(findings),
        duration_seconds=elapsed,
    )
    return findings


async def _collect_modules(
    ctx: ScanContext, config: TargetConfig
) -> tuple[list[str], list[Finding]]:
    findings: list[Finding] = []
    modules_run: list[str] = []

    if config.modules.bola and config.modules.bola.enabled:
        try:
            from modules.bola import run_bola
        except ImportError as exc:
            log.warning("module_not_implemented", module="bola", error=str(exc))
        else:
            modules_run.append("bola")
            findings.extend(
                await _safe_run_module("bola", run_bola, ctx, config.modules.bola)
            )

    if config.modules.race and config.modules.race.enabled:
        try:
            from modules.race import run_race
        except ImportError as exc:
            log.warning("module_not_implemented", module="race", error=str(exc))
        else:
            modules_run.append("race")
            findings.extend(
                await _safe_run_module("race", run_race, ctx, config.modules.race)
            )

    if config.modules.auth and config.modules.auth.enabled:
        try:
            from modules.auth import run_auth
        except ImportError as exc:
            log.warning("module_not_implemented", module="auth", error=str(exc))
        else:
            modules_run.append("auth")
            findings.extend(
                await _safe_run_module("auth", run_auth, ctx, config.modules.auth)
            )

    if config.modules.business_logic and config.modules.business_logic.enabled:
        try:
            from modules.business_logic import run_business_logic
        except ImportError as exc:
            log.warning(
                "module_not_implemented", module="business_logic", error=str(exc)
            )
        else:
            modules_run.append("business_logic")
            findings.extend(
                await _safe_run_module(
                    "business_logic",
                    run_business_logic,
                    ctx,
                    config.modules.business_logic,
                )
            )

    if config.modules.webhook and config.modules.webhook.enabled:
        try:
            from modules.webhook import run_webhook
        except ImportError as exc:
            log.warning("module_not_implemented", module="webhook", error=str(exc))
        else:
            modules_run.append("webhook")
            findings.extend(
                await _safe_run_module(
                    "webhook", run_webhook, ctx, config.modules.webhook
                )
            )

    return modules_run, findings


def _write_jsonl(findings: list[Finding], output_dir: Path, timestamp: str) -> Path:
    path = output_dir / f"scan_{timestamp}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(f.model_dump_json() + "\n")
    return path


async def run_scan(config_path: Path, output_dir: Path) -> ScanResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    config = load_target_config(config_path)
    log.info("scan_started", target=config.name, base_url=config.base_url)

    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()

    async with AsyncExitStack() as stack:
        ctx = await build_context(config, stack)
        modules_run, findings = await _collect_modules(ctx, config)

    finished = datetime.now(timezone.utc)
    duration = round(time.perf_counter() - t0, 3)

    for f in findings:
        if f.target is None:
            f.target = config.name

    result = ScanResult(
        target=config.name,
        base_url=config.base_url,
        started_at=started,
        finished_at=finished,
        duration_seconds=duration,
        modules_run=modules_run,
        findings=findings,
    )

    timestamp = started.strftime("%Y%m%d_%H%M%S")
    jsonl_path = _write_jsonl(findings, output_dir, timestamp)
    log.info(
        "scan_complete",
        target=config.name,
        duration_seconds=duration,
        finding_count=len(findings),
        modules_run=modules_run,
        jsonl=str(jsonl_path),
    )

    try:
        from .reporter import write_html_report
    except ImportError:
        log.info("html_report_skipped", reason="reporter not yet implemented")
    else:
        try:
            html_path = write_html_report(result, output_dir, timestamp)
            log.info("html_report_written", path=str(html_path))
        except Exception as exc:
            log.error("html_report_failed", error=str(exc))

    return result
