# Security Policy

## ⚠️ This repository contains a deliberately vulnerable component

`target/` (BrokenCheckout) is a FastAPI application built **with intentional
security flaws** to serve as the canonical test target for the Fracture
scanner. Every flaw is documented in [`docs/vulnerability-index.md`](docs/vulnerability-index.md)
with its CWE identifier and the correct production-grade remediation.

**Do not deploy BrokenCheckout to a publicly-reachable network.** It is
designed to be exploitable. The provided `docker-compose.yml` binds the
target port to `127.0.0.1` (loopback only) for exactly this reason.

The hardcoded credentials in `target/auth.py` (`JWT_SECRET = "secret"`),
`target/routers/webhooks.py` (`WEBHOOK_SECRET = "whsec_test_secret"`), and
`scanner/config/targets/brokencheckout.yaml` (`password: password123`) are
**test fixtures**, not real secrets. They are part of the deliberate
vulnerability surface. If your secret scanner flags them, mark this repo
as a test/educational fixture in your scanner configuration.

## Authorized use only

The Fracture scanner is a security-testing tool. Use it **only** against
systems you own or have explicit written authorization to test.
Unauthorized scanning of third-party systems may violate computer-misuse
laws in your jurisdiction (e.g. the Computer Fraud and Abuse Act in the
US, the Computer Misuse Act in the UK, equivalent statutes elsewhere).

## Reporting a vulnerability in Fracture itself

If you discover a security issue in the **scanner** (`scanner/`) - for
example, a crafted target response that crashes the scanner, a vulnerability
that could be exploited via a malicious target YAML config, or a finding-
serialization issue that could lead to log injection - please report it via
GitHub's private vulnerability disclosure:

→ https://github.com/Mahmoud-Berkoti/Fracture/security/advisories/new

Do not open a public issue for security-sensitive reports.

Issues in BrokenCheckout (`target/`) are **not** considered vulnerabilities -
they are documented intentional flaws and the entire point of the project.

## Supported versions

| Version | Supported |
|---------|-----------|
| main    | ✅        |
| anything else | ❌  |

This is a single-branch project. Security fixes land on `main`.

## Dependencies

All Python dependencies are pinned in `scanner/requirements.txt` and
`target/requirements.txt`. To audit them against the public CVE database:

```bash
pip install pip-audit
pip-audit -r scanner/requirements.txt
pip-audit -r target/requirements.txt
```
