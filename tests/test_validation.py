"""Attack-validation suite - section 7 of the spec.

Runs the scanner end-to-end against an in-process BrokenCheckout and
asserts that each intentional vulnerability surfaces a finding of the
expected CWE + severity. This both proves the scanner works and
documents exactly which vulnerabilities BrokenCheckout exposes.

The spec sketches `run_module("bola", target="brokencheckout")` as the
test entry point; that helper doesn't exist in our code, so the tests
use the production `run_scan(config_path, output_dir)` API and assert
against the resulting `ScanResult.findings`. Same property under test;
fewer hidden helpers.

Run with: `.venv/bin/python -m pytest tests -v` (or via docker compose).
"""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCANNER_DIR = ROOT / "scanner"
sys.path.insert(0, str(SCANNER_DIR))

from core.runner import run_scan  # noqa: E402


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture(scope="session")
def target_url(tmp_path_factory):
    """Spawn BrokenCheckout via uvicorn on a free local port."""
    port = _free_port()
    target_dir = ROOT / "target"
    tmp_db = tmp_path_factory.mktemp("data") / "test.db"
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_db}",
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(target_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                r = httpx.get(f"{base}/health", timeout=0.5)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            stdout, stderr = proc.communicate(timeout=2)
            raise RuntimeError(
                f"Target did not respond on {base}/health within 30s.\n"
                f"stdout: {stdout.decode(errors='replace')[:500]}\n"
                f"stderr: {stderr.decode(errors='replace')[:500]}"
            )
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture(scope="session")
def scan_result(target_url, tmp_path_factory):
    src = SCANNER_DIR / "config" / "targets" / "brokencheckout.yaml"
    raw = yaml.safe_load(src.read_text())
    raw["base_url"] = target_url
    tmp_cfg = tmp_path_factory.mktemp("cfg") / "test.yaml"
    tmp_cfg.write_text(yaml.safe_dump(raw))
    output_dir = tmp_path_factory.mktemp("output")
    return asyncio.run(run_scan(tmp_cfg, output_dir))


# ----- BOLA -----

def test_bola_critical_cwe_639(scan_result):
    bola = [f for f in scan_result.findings if f.module == "bola"]
    assert any(f.cwe_id == "CWE-639" for f in bola), \
        f"expected CWE-639 BOLA finding; got {[f.cwe_id for f in bola]}"
    assert any(f.severity == "critical" for f in bola), \
        f"expected critical BOLA finding; got {[f.severity for f in bola]}"


# ----- Race conditions -----

def test_race_critical_cwe_362(scan_result):
    race = [f for f in scan_result.findings if f.module == "race"]
    assert any(f.cwe_id == "CWE-362" for f in race), \
        f"expected CWE-362 race finding; got {[f.cwe_id for f in race]}"


# ----- Webhook -----

def test_webhook_signature_bypass(scan_result):
    webhook = [f for f in scan_result.findings if f.module == "webhook"]
    assert any("signature" in f.title.lower() for f in webhook), \
        f"expected signature-bypass finding; got {[f.title for f in webhook]}"


# ----- Auth -----

def test_auth_alg_none_accepted(scan_result):
    auth_findings = [f for f in scan_result.findings if f.module == "auth"]
    assert any(f.cwe_id == "CWE-347" for f in auth_findings), \
        f"expected CWE-347 alg:none finding; got {[f.cwe_id for f in auth_findings]}"


def test_auth_weak_secret_detected(scan_result):
    auth_findings = [f for f in scan_result.findings if f.module == "auth"]
    assert any(f.cwe_id == "CWE-798" for f in auth_findings), \
        f"expected CWE-798 weak-secret finding; got {[f.cwe_id for f in auth_findings]}"


# ----- Business logic -----

def test_business_logic_negative_amount(scan_result):
    bl = [f for f in scan_result.findings if f.module == "business_logic"]
    assert any("negative" in f.title.lower() for f in bl), \
        f"expected negative-amount finding; got {[f.title for f in bl]}"


# ----- Universal contract: every finding is fully-formed -----

def test_every_finding_has_required_fields(scan_result):
    assert scan_result.findings, "scan produced zero findings - modules misconfigured?"
    for f in scan_result.findings:
        assert f.module, f"finding missing module: {f}"
        assert f.severity in {"critical", "high", "medium", "low", "info"}, \
            f"invalid severity: {f.severity}"
        assert f.title, f"finding missing title: {f}"
        assert f.description, f"finding missing description: {f}"
        assert f.remediation, "every finding must include remediation"
        assert f.reproduction_steps, "every finding must include reproduction steps"
