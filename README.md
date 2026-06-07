# Fracture

> ⚠️ **Authorized use only.** This repository contains an intentionally vulnerable component (`target/`). It must not be deployed to a public network. The scanner (`scanner/`) is a security-testing tool — use it only against systems you own or have explicit written authorization to test. See [`SECURITY.md`](SECURITY.md) for details.

**Payment API security testing framework.** Surfaces the vulnerability classes endemic to fintech infrastructure — broken object-level authorization, race conditions on transaction endpoints, JWT auth bypass, business-logic flaws in financial operations, and webhook signature failures — none of which generic API scanners catch reliably.

Ships as two components in one repo: a deliberately-vulnerable target API (**BrokenCheckout**) and the **Fracture scanner** that runs a structured attack suite against any configured target. One command (`docker compose up`) starts the target, waits for it to become healthy, then runs the full scan and writes JSONL + HTML reports to `./output/`.

Sample scan against BrokenCheckout produces **14 findings across 5 modules in ~0.5s** (7 critical, 4 high, 2 medium, 0 low/info).

---

## Architecture

```
┌──────────────────────┐        HTTP         ┌──────────────────────┐
│  Fracture scanner    │ ──────────────────► │  BrokenCheckout      │
│  (Python 3.11,       │                     │  (FastAPI + SQLite)  │
│   asyncio, httpx)    │ ◄────────────────── │   intentional flaws  │
│                      │      JSON/2xx       │                      │
│  modules/            │                     │  routers/            │
│   ├── bola.py        │                     │   ├── payments.py    │
│   ├── race.py        │                     │   ├── refunds.py     │
│   ├── auth.py        │                     │   ├── webhooks.py    │
│   ├── business_logic │                     │   └── customers.py   │
│   └── webhook.py     │                     │                      │
└────────┬─────────────┘                     └──────────────────────┘
         │
         ▼
   ./output/scan_<ts>.jsonl    (one finding per line; SIEM-ingestible)
   ./output/report_<ts>.html   (self-contained, dark-themed, with chart)
```

---

## Quick start

```bash
git clone <this repo>
cd fracture
docker compose up
```

That's it. On a fresh machine it takes ~30 seconds: target builds and starts (~10s), passes its health check, then the scanner runs the full attack suite (~5s) and writes results to `./output/`. Open `./output/report_<timestamp>.html` in any browser.

### Local development (no Docker)

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r scanner/requirements.txt -r target/requirements.txt pytest

# Terminal 1 — start BrokenCheckout
cd target && ../.venv/bin/uvicorn main:app --port 8000

# Terminal 2 — point the scanner at it
cd scanner && ../.venv/bin/python main.py --target brokencheckout --output ../output \
    --config-dir config/targets
# (override base_url in YAML to http://localhost:8000 first)
```

### Run the validation suite

```bash
.venv/bin/python -m pytest tests -v
```

The test fixture spawns BrokenCheckout in a subprocess and asserts that every documented intentional vulnerability surfaces with the correct CWE.

---

## Vulnerability index

The full table — every flaw, file, route, detection signal, and correct remediation — lives in [`docs/vulnerability-index.md`](docs/vulnerability-index.md). The short version:

| # | Class | Affected route | CWE | Severity |
|---|---|---|---|---|
| 1 | JWT `alg:none` accepted | (all auth-gated routes) | CWE-347 | Critical |
| 2 | Hardcoded JWT signing secret | (all auth-gated routes) | CWE-798 | High |
| 3 | JWT `exp` not validated | (all auth-gated routes) | CWE-613 | High |
| 4 | BOLA on payment methods | `GET /v1/payment-methods/{id}` | CWE-639 | Critical |
| 5 | BOLA on invoices | `GET /v1/invoices/{id}` | CWE-639 | Critical |
| 6 | BOLA on subscriptions | `GET /v1/customers/{id}/subscriptions` | CWE-639 | Critical |
| 7 | BOLA + race on refunds | `POST /v1/refunds` | CWE-639, CWE-362 | Critical |
| 8 | Coupon race condition | `POST /v1/charges` (with coupon) | CWE-362 | Critical |
| 9 | Negative / zero / overflow amount | `POST /v1/charges` | CWE-20, CWE-190 | Critical / Medium / High |
| 10 | Arbitrary currency code | `POST /v1/charges` | CWE-20 | Medium |
| 11 | Webhook signature optional | `POST /v1/webhooks` | CWE-345 | Critical |
| 12 | Webhook replay window unenforced | `POST /v1/webhooks` | CWE-294 | High |

---

## What Fracture does **not** do

Honest scoping matters for a security tool. Fracture is purpose-built and narrow:

- **Not a production scanner.** Concurrency defaults to N=20; that's enough to trigger race conditions on a local target with millisecond response times. It is not load-tested at production scale.
- **JWT bearer tokens only.** OAuth 2.0 flows (authorization code, device code, refresh-token rotation, PKCE) are out of scope. So is OpenID Connect.
- **REST only.** No GraphQL, no gRPC, no JSON-RPC.
- **No SQL injection, XSS, or CSRF probes.** Those are well-covered by general-purpose scanners (`sqlmap`, Burp, OWASP ZAP). Running Fracture and one of those in tandem is the intended workflow.
- **No mass targeting.** Single-target per invocation; no scanning of CIDR ranges or domain lists.
- **No detection evasion.** All requests advertise `User-Agent: Fracture/1.0` and use unobscured payloads. This is a test tool, not an offensive one.
- **No persistence.** The scanner is stateless across runs — every invocation re-authenticates and re-probes from scratch.

---

## Output formats

### `output/scan_<timestamp>.jsonl`

Line-delimited JSON; one finding per line. `grep`-able, streamable, directly ingestible by SIEM platforms (Sentinel, Splunk, Elastic). Example:

```jsonl
{"module":"bola","severity":"critical","title":"BOLA: cross-user read on /v1/payment-methods/{id}","cwe_id":"CWE-639", ...}
```

### `output/report_<timestamp>.html`

Self-contained dark-themed HTML report. Renders correctly with no network access (only Google Fonts is loaded externally, and the page is readable without it). Includes severity-distribution donut chart, attack-module timeline with pass/fail indicators, and expandable finding cards with full reproduction steps + evidence JSON.

The report is designed to be the artifact you attach to a security review document — not a debugging dump.

---

## Project layout

```
fracture/
├── docker-compose.yml          # one-command boot
├── scanner/                    # Fracture scanner
│   ├── main.py                 # CLI entry
│   ├── config/targets/         # per-target YAML configs
│   ├── core/                   # models, session, runner, reporter
│   ├── modules/                # one file per attack class
│   └── report/templates/       # Jinja2 HTML template
├── target/                     # BrokenCheckout (deliberately vulnerable)
│   ├── main.py                 # FastAPI entry
│   ├── auth.py                 # JWT with documented flaws
│   ├── database.py             # async SQLite + SQLAlchemy
│   ├── models.py               # ORM models
│   └── routers/                # one file per resource group
├── tests/
│   └── test_validation.py      # asserts BrokenCheckout vulns are detected
├── docs/
│   ├── threat-model.md         # what we test for and why
│   └── vulnerability-index.md  # every intentional flaw + the correct fix
└── output/                     # scan artifacts (jsonl + html)
```

---

## Configuration

Targets are configured as YAML files under `scanner/config/targets/`. The bundled `brokencheckout.yaml` is the canonical example. To point Fracture at a different target, copy that file, swap `base_url` and `auth.credentials`, then run with `--target <new-name>`. See [`scanner/config/targets/brokencheckout.yaml`](scanner/config/targets/brokencheckout.yaml) for the full schema.

---

## License

[MIT](LICENSE). BrokenCheckout is deliberately vulnerable and must not be deployed to a public-internet network. See [`SECURITY.md`](SECURITY.md) for the full responsible-use statement and how to report vulnerabilities in the scanner itself.
