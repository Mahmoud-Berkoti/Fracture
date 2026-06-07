# Fracture - Payment API Security Testing Framework
## Technical Specification v1.0

---

## 1. Project Overview

Fracture is an automated offensive security testing framework purpose-built for REST APIs that handle payment flows. It is designed to surface vulnerability classes that are endemic to fintech infrastructure: broken object-level authorization, race conditions in transaction endpoints, authentication bypass, business logic flaws specific to financial operations, and webhook security failures.

The core thesis of Fracture is that generic API scanners miss the vulnerability classes that actually matter in payment systems. A tool like Burp Suite will find SQL injection. It will not find that your refund endpoint processes concurrent requests without idempotency guarantees, or that your webhook handler accepts replayed events with valid signatures from 72 hours ago. Fracture is built to find exactly those things.

Fracture ships as two components: a deliberately vulnerable target API called **BrokenCheckout** that serves as the test environment, and the Fracture scanner itself which runs a structured attack suite against any configured target. Both components run via a single `docker compose up` command with zero additional setup.

---

## 2. Threat Model and Vulnerability Scope

Fracture targets the following vulnerability classes in priority order. Each class maps directly to real-world fintech breach patterns and is documented in public security research from Stripe, PayPal, and Shopify engineering teams.

### 2.1 Broken Object Level Authorization (BOLA / IDOR)

Payment APIs routinely expose resource identifiers in URLs and request bodies. Without per-request ownership validation, authenticated users can access or manipulate resources belonging to other users by substituting identifiers.

**Attack pattern:** Authenticate as User A, capture a resource identifier belonging to User B, issue requests against that identifier using User A's session token.

**Target endpoints in payment context:**
- `GET /v1/payment-methods/{id}` - retrieve another user's saved card
- `GET /v1/invoices/{id}` - read another user's invoice
- `POST /v1/refunds` with a `charge_id` belonging to another user
- `GET /v1/customers/{id}/subscriptions` - enumerate another user's subscriptions

**Detection signal:** HTTP 200 response with data payload when the requesting user does not own the resource. HTTP 403 or 404 is the correct response.

### 2.2 Race Conditions in Transaction Endpoints

Financial transaction endpoints are high-value race condition targets. Operations that should be atomic, such as applying a discount code, issuing a refund, or charging a stored payment method, can be exploited by flooding concurrent requests within a narrow time window.

**Attack patterns:**
- **Double refund:** Send N concurrent refund requests for the same charge before the first completes and marks the charge as refunded
- **Coupon reuse:** Send N concurrent checkout requests using a single-use coupon code before the first marks it consumed
- **Double spend:** Send N concurrent payment attempts against an account balance before the first deducts it
- **Subscription upgrade race:** Send concurrent upgrade and downgrade requests to land in an inconsistent billing state

**Detection signal:** Any response set where more than one request returns HTTP 200 with a successful transaction result for an operation that should only succeed once.

**Technical requirement:** Detection requires true async concurrent HTTP requests dispatched within the same millisecond window. This is why `httpx` with `asyncio` is the correct tool. Sequential requests or thread-pool-based concurrency will not reliably trigger these conditions.

### 2.3 Authentication and Authorization Bypass

**JWT weaknesses:**
- Algorithm confusion: send a token signed with `alg: none`
- Algorithm substitution: send an RS256 token re-signed with the public key using HS256
- Expired token acceptance: send tokens with `exp` in the past
- Claim manipulation: modify `sub`, `role`, or `scope` claims and re-encode without re-signing

**Token security:**
- Token reuse after logout
- Insufficient token entropy allowing brute force
- Predictable token generation patterns

**Session fixation:**
- Pre-authentication session tokens that persist post-authentication

### 2.4 Business Logic Flaws in Financial Operations

These are the vulnerability class that purely technical scanners never find because they require understanding the business domain.

**Attack patterns:**
- **Negative amount injection:** Submit `amount: -100` to a charge endpoint and observe whether a credit is issued
- **Currency confusion:** Submit `amount: 100, currency: "JPY"` for an endpoint priced in USD and observe whether the conversion is applied server-side or client-side
- **Integer overflow:** Submit amounts near `INT32_MAX` or `INT64_MAX` and observe wrapping behavior
- **Free tier abuse:** Exhaust a trial, reset account state via API, re-activate trial
- **Discount stacking:** Apply multiple mutually exclusive promotions in a single transaction
- **Zero amount transactions:** Submit `amount: 0` and observe whether the transaction succeeds and what state it creates

### 2.5 Webhook Security

Webhooks are an afterthought in most payment API security reviews. They are not an afterthought in production incident post-mortems.

**Attack patterns:**
- **Signature bypass:** Send a webhook payload with a missing, empty, or malformed signature header and observe whether the handler processes it
- **Replay attack:** Capture a legitimate webhook event, re-send it after the replay window has expired, observe whether the handler processes it again
- **Event injection:** Send a crafted `payment_intent.succeeded` event for a payment that was never initiated
- **Timestamp manipulation:** Send a webhook with a `t=` timestamp value in the future or distant past

**Detection signal:** Any webhook handler that processes a request with an invalid or missing signature, or processes a replayed event outside the tolerance window.

---

## 3. Architecture

```
fracture/
├── docker-compose.yml
├── README.md
├── scanner/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                  # CLI entrypoint
│   ├── config/
│   │   └── targets/
│   │       └── brokencheckout.yaml   # Target configuration
│   ├── core/
│   │   ├── __init__.py
│   │   ├── runner.py            # Orchestrates attack modules
│   │   ├── session.py           # Manages authenticated HTTP sessions
│   │   ├── reporter.py          # Generates HTML and JSONL reports
│   │   └── models.py            # Pydantic models for findings and config
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── bola.py              # BOLA/IDOR attack module
│   │   ├── race.py              # Race condition attack module
│   │   ├── auth.py              # Authentication bypass module
│   │   ├── business_logic.py   # Business logic flaw module
│   │   └── webhook.py           # Webhook security module
│   └── report/
│       ├── templates/
│       │   └── report.html.j2   # Jinja2 report template
│       └── static/
│           └── chart.js         # Vendored Chart.js
├── target/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                  # BrokenCheckout API entrypoint
│   ├── database.py              # SQLite setup and session management
│   ├── models.py                # SQLAlchemy models
│   ├── auth.py                  # JWT implementation with intentional flaws
│   └── routers/
│       ├── payments.py          # Payment endpoints with intentional flaws
│       ├── refunds.py           # Refund endpoints vulnerable to race conditions
│       ├── webhooks.py          # Webhook handler with signature bypass flaw
│       └── customers.py        # Customer endpoints vulnerable to BOLA
└── docs/
    ├── threat-model.md
    └── vulnerability-index.md
```

---

## 4. BrokenCheckout - Deliberately Vulnerable Target API

BrokenCheckout is a FastAPI application that simulates a payment processing API with intentional security flaws. It is the canonical test target for Fracture and ships as part of the same repository.

### 4.1 Intentional Vulnerabilities

Every vulnerability in BrokenCheckout is documented in `docs/vulnerability-index.md` with the corresponding CWE identifier and the correct remediation. This documentation is intentional: it demonstrates understanding of both the flaw and the fix, which is what security engineering interviews actually probe.

**BOLA in payment method retrieval:**
```python
# Vulnerable: no ownership check
@router.get("/v1/payment-methods/{payment_method_id}")
async def get_payment_method(payment_method_id: str, current_user: User = Depends(get_current_user)):
    method = db.query(PaymentMethod).filter(
        PaymentMethod.id == payment_method_id
    ).first()
    return method
```

**Race condition in refund processing:**
```python
# Vulnerable: check-then-act without atomic lock
@router.post("/v1/refunds")
async def create_refund(refund: RefundRequest, current_user: User = Depends(get_current_user)):
    charge = db.query(Charge).filter(Charge.id == refund.charge_id).first()
    if charge.refunded:
        raise HTTPException(status_code=400, detail="Already refunded")
    await asyncio.sleep(0.05)  # Simulates processing latency, creates race window
    charge.refunded = True
    db.commit()
    return {"refund_id": str(uuid4()), "amount": charge.amount}
```

**Webhook signature bypass:**
```python
# Vulnerable: signature validation is optional
@router.post("/v1/webhooks")
async def handle_webhook(request: Request):
    signature = request.headers.get("Fracture-Signature")
    if signature:  # Only validates if header is present
        verify_signature(await request.body(), signature)
    payload = await request.json()
    process_event(payload)
```

**Negative amount acceptance:**
```python
# Vulnerable: no amount validation
@router.post("/v1/charges")
async def create_charge(charge: ChargeRequest, current_user: User = Depends(get_current_user)):
    # Missing: if charge.amount <= 0: raise HTTPException(...)
    transaction = process_payment(current_user, charge.amount)
    return transaction
```

### 4.2 Database Schema

BrokenCheckout uses SQLite with SQLAlchemy. Tables: `users`, `payment_methods`, `charges`, `refunds`, `webhook_events`, `coupons`, `subscriptions`. Schema is defined in `database.py` and initialized on startup.

### 4.3 Authentication

BrokenCheckout implements JWT authentication with the following intentional weaknesses:
- Accepts `alg: none` tokens
- Does not validate token expiry on certain endpoints
- Uses a hardcoded secret key (`secret`) making signatures trivially forgeable

---

## 5. Fracture Scanner

### 5.1 Configuration

Each target is defined as a YAML file under `scanner/config/targets/`. The BrokenCheckout configuration:

```yaml
name: BrokenCheckout
base_url: http://target:8000
auth:
  type: jwt
  login_endpoint: /v1/auth/login
  credentials:
    - username: alice@example.com
      password: password123
    - username: bob@example.com
      password: password123
modules:
  bola:
    enabled: true
    endpoints:
      - path: /v1/payment-methods/{id}
        method: GET
        id_param: id
      - path: /v1/invoices/{id}
        method: GET
        id_param: id
  race:
    enabled: true
    concurrency: 20
    endpoints:
      - path: /v1/refunds
        method: POST
        body:
          charge_id: "{charge_id}"
      - path: /v1/charges
        method: POST
        body:
          amount: 1000
          currency: usd
          coupon: SAVE10
  auth:
    enabled: true
    endpoints:
      - path: /v1/payment-methods
        method: GET
  business_logic:
    enabled: true
    endpoints:
      - path: /v1/charges
        method: POST
  webhook:
    enabled: true
    endpoint: /v1/webhooks
    secret: whsec_test_secret
```

### 5.2 Core Runner

`runner.py` orchestrates module execution sequentially, collects findings into a unified list, and passes results to the reporter. Each module returns a list of `Finding` objects defined in `models.py`.

```python
@dataclass
class Finding:
    module: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    evidence: dict          # Raw request/response data
    cwe_id: Optional[str]
    reproduction_steps: list[str]
    remediation: str
```

Every finding includes reproduction steps and remediation guidance. This is non-negotiable. A security tool that tells you something is broken but not how to reproduce or fix it is useless.

### 5.3 Race Condition Module

This is the most technically interesting module and the one most worth explaining in interviews. The core challenge is dispatching N requests within the same millisecond window to reliably trigger the race condition.

```python
async def attack_race_condition(session: httpx.AsyncClient, endpoint: EndpointConfig, n: int = 20) -> list[Finding]:
    findings = []
    
    # Build all requests before dispatching any
    requests = [
        session.request(
            method=endpoint.method,
            url=endpoint.path,
            json=endpoint.body
        )
        for _ in range(n)
    ]
    
    # Dispatch all requests concurrently within the same event loop tick
    responses = await asyncio.gather(*requests, return_exceptions=True)
    
    successes = [r for r in responses if isinstance(r, httpx.Response) and r.status_code == 200]
    
    if len(successes) > 1:
        findings.append(Finding(
            module="race",
            severity="critical",
            title=f"Race condition in {endpoint.path}",
            description=f"{len(successes)} of {n} concurrent requests succeeded for an operation that should succeed at most once.",
            evidence={
                "concurrent_requests": n,
                "successful_responses": len(successes),
                "sample_response": successes[0].json()
            },
            cwe_id="CWE-362",
            reproduction_steps=[
                f"Authenticate as a valid user",
                f"Send {n} concurrent POST requests to {endpoint.path} within the same time window",
                f"Observe that {len(successes)} requests return HTTP 200"
            ],
            remediation="Implement database-level locking or idempotency keys. Use SELECT FOR UPDATE or an atomic compare-and-swap operation before committing the transaction."
        ))
    
    return findings
```

### 5.4 BOLA Module

The BOLA module authenticates as two distinct users, has User A create resources, then attempts to access those resources as User B.

```python
async def attack_bola(sessions: dict[str, httpx.AsyncClient], endpoint: EndpointConfig) -> list[Finding]:
    # User A creates a resource
    create_response = await sessions["alice"].post(endpoint.create_path, json=endpoint.create_body)
    resource_id = create_response.json().get("id")
    
    # User B attempts to access User A's resource
    access_response = await sessions["bob"].get(f"{endpoint.path}/{resource_id}")
    
    if access_response.status_code == 200:
        return [Finding(
            module="bola",
            severity="critical",
            title=f"BOLA vulnerability in {endpoint.path}",
            description="Authenticated user can access resources belonging to other users by manipulating object identifiers.",
            evidence={
                "resource_owner": "alice",
                "accessing_user": "bob",
                "resource_id": resource_id,
                "response_status": access_response.status_code,
                "response_body": access_response.json()
            },
            cwe_id="CWE-639",
            reproduction_steps=[
                "Authenticate as User A and create a payment method",
                "Note the returned resource ID",
                "Authenticate as User B",
                f"Send GET {endpoint.path}/{{resource_id}} using User B's token",
                "Observe HTTP 200 with User A's data"
            ],
            remediation="Validate resource ownership on every request. Query must include both the resource ID and the authenticated user's ID: WHERE id = ? AND user_id = ?"
        )]
    return []
```

### 5.5 Webhook Module

```python
async def attack_webhook(client: httpx.AsyncClient, config: WebhookConfig) -> list[Finding]:
    findings = []
    test_payload = json.dumps({"type": "payment_intent.succeeded", "data": {"amount": 10000}})
    
    # Test 1: Missing signature header
    response = await client.post(config.endpoint, content=test_payload, headers={"Content-Type": "application/json"})
    if response.status_code == 200:
        findings.append(Finding(
            module="webhook",
            severity="critical",
            title="Webhook signature validation missing",
            description="Webhook endpoint processes requests without requiring a valid signature header.",
            evidence={"request_headers": {}, "response_status": response.status_code},
            cwe_id="CWE-345",
            reproduction_steps=[
                f"Send POST {config.endpoint} with a valid JSON payload",
                "Omit the signature header entirely",
                "Observe HTTP 200 - event is processed"
            ],
            remediation="Require the signature header on all webhook requests. Reject with HTTP 400 if the header is missing or invalid before processing any payload content."
        ))
    
    # Test 2: Replay attack outside tolerance window
    timestamp = int(time.time()) - 400  # 400 seconds ago, outside 300s tolerance
    body_to_sign = f"{timestamp}.{test_payload}".encode()
    signature = hmac.new(config.secret.encode(), body_to_sign, hashlib.sha256).hexdigest()
    replay_headers = {
        "Content-Type": "application/json",
        "Fracture-Signature": f"t={timestamp},v1={signature}"
    }
    response = await client.post(config.endpoint, content=test_payload, headers=replay_headers)
    if response.status_code == 200:
        findings.append(Finding(
            module="webhook",
            severity="high",
            title="Webhook replay attack possible",
            description="Webhook handler accepts events with timestamps outside the replay tolerance window.",
            evidence={"timestamp_age_seconds": 400, "response_status": response.status_code},
            cwe_id="CWE-294",
            reproduction_steps=[
                "Capture a legitimate webhook event with a valid signature",
                "Re-send the same event with the original timestamp after the tolerance window has expired",
                "Observe HTTP 200 - replayed event is processed again"
            ],
            remediation="Reject webhook events where the timestamp is more than 300 seconds old. Store processed event IDs and reject duplicates."
        ))
    
    return findings
```

---

## 6. Reporting

### 6.1 JSONL Audit Log

Every scan writes a line-delimited JSON log to `./output/scan_{timestamp}.jsonl`. Each line is one finding serialized as JSON. This format is chosen deliberately: it is grep-able, streamable, and directly ingestible by SIEM platforms like Azure Sentinel, which mirrors real security tooling conventions.

### 6.2 HTML Report - Frontend Design Requirements

After each scan, Fracture generates a self-contained HTML report at `./output/report_{timestamp}.html` using Jinja2 templating. This report is a first-class visual deliverable. It must look nothing like a generic security dashboard. The design goal is a report that a Stripe or Shopify security engineer opens and immediately recognizes as something built with taste and intent.

---

#### 6.2.1 Design System Setup

Before writing a single line of frontend code, run the UI/UX Pro Max skill search tool to pull design recommendations appropriate for this project:

```bash
# Install the skill
npx uipro init

# Query for relevant design direction
python3 .claude/skills/ui-ux-pro-max/scripts/search.py "security dashboard dark theme" --domain style
python3 .claude/skills/ui-ux-pro-max/scripts/search.py "data visualization fintech" --domain chart
python3 .claude/skills/ui-ux-pro-max/scripts/search.py "security tool typography" --domain typography
python3 .claude/skills/ui-ux-pro-max/scripts/search.py "dark SaaS dashboard" --domain color --stack html-tailwind
```

Apply the returned CSS keywords, font pairings, color palettes, and chart type recommendations as the foundation of the design system. Do not proceed to implementation until the search results have been reviewed and a design direction has been chosen.

---

#### 6.2.2 Visual Design Direction

The report must use a **dark, high-contrast aesthetic** that feels closer to a terminal security tool than a business intelligence dashboard. Reference: Vercel's dashboard, Linear's issue tracker, Warp terminal. Avoid: Bootstrap default, Material UI defaults, any light-mode-first design.

**Color system:**
- Background: deep near-black, not pure `#000000`, something like `#0a0a0f` or `#0d1117`
- Surface: one step up from background, `#13151a` or `#161b22`
- Border: subtle, `1px solid rgba(255,255,255,0.08)`
- Critical severity: `#ff4444` or a deep red that reads as danger without being garish
- High severity: `#ff8c00`
- Medium severity: `#ffd700`
- Low severity: `#4fc3f7`
- Info: `#9e9e9e`
- Accent/primary: a single electric color used sparingly, `#6366f1` indigo or `#00d4ff` cyan

**Typography:**
- Use Google Fonts. Query the skill for the best pairing for a security tool.
- Monospace font for all code blocks, evidence JSON, and endpoint paths. `JetBrains Mono` or `Fira Code`.
- Sans-serif for all UI text. `Inter` or `DM Sans`.
- Import both via a single Google Fonts `<link>` tag.

---

#### 6.2.3 Layout and Component Specifications

**Header:**
- Full-width dark bar with the Fracture wordmark on the left
- Scan metadata inline on the right: target name, timestamp, total duration, modules run
- A single colored status pill: `CRITICAL FINDINGS` in red or `CLEAN` in green

**Executive Summary Strip:**
- Horizontal row of stat cards immediately below the header
- One card per severity level showing count: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Each card has the severity color as a left border accent and the count in a large monospace font
- Cards animate in on page load with a subtle fade-up, staggered 100ms per card

**Attack Module Timeline:**
- A horizontal timeline showing which modules ran, in order, with pass/fail indicators
- Each module node is a pill: module name + finding count + colored dot
- Clicking a module node smooth-scrolls to that module's findings section

**Finding Cards:**
- Each finding renders as a card with a left border in the severity color
- Card header: severity badge + CWE ID chip + finding title
- Expandable body: description, then reproduction steps as a numbered list, then remediation in a highlighted callout box
- Evidence section: collapsible, renders the raw request/response JSON in a syntax-highlighted monospace code block with a copy button
- Cards animate in on scroll using `IntersectionObserver`, not a library

**Chart:**
- Donut chart showing finding distribution by severity using Chart.js
- Dark background, no gridlines, custom legend below the chart
- Animate on page load with a 600ms ease-out draw animation

**Liquid/Smooth Interactions:**
- All expand/collapse transitions use CSS `max-height` animation, not `display:none` toggle, so the motion is smooth
- Hover states on cards lift with `transform: translateY(-2px)` and a subtle box-shadow increase
- The copy button on code blocks shows a checkmark for 1500ms then reverts, with a CSS transition on the icon swap
- Scroll behavior is `scroll-behavior: smooth` on the root
- All color transitions use `transition: all 0.2s ease`
- No jarring state changes anywhere. Every interaction has a motion response.

---

#### 6.2.4 Self-Contained Requirement

The report HTML file must be fully self-contained with zero external dependencies at render time:

- Chart.js must be inlined as a `<script>` block, not loaded from a CDN
- Google Fonts must be the only external request, loaded via `<link>` in `<head>`
- All CSS must be in a `<style>` block in `<head>`, no external stylesheet
- All JavaScript must be in a `<script>` block before `</body>`
- The Jinja2 template renders scan data directly into the HTML at generation time, no client-side API calls

This constraint exists because the report must render correctly when opened as a local file with no network access.

---

#### 6.2.5 AI-Generated Background Assets

Use **Gemini 2.0 Flash** (Google's image generation model) to generate one background texture or hero graphic for the report header. The prompt to use:

> "Abstract dark cyberpunk circuit board texture, deep navy and black, subtle glowing cyan trace lines, no text, no logos, seamless tile, suitable for a dark UI background, 1200x400px"

Embed the generated image as a base64 data URI in the Jinja2 template so it remains self-contained. Use it as the report header background with a dark overlay so text remains readable.

---

#### 6.2.6 21st.dev Component References

Pull interaction patterns and component inspiration from `https://21st.dev`. Specifically reference:
- Their animated stat card patterns for the executive summary strip
- Their code block component for the evidence JSON display
- Their timeline component for the attack module timeline

Do not import their components as a dependency. Study the implementation patterns and reimplement them in vanilla CSS and JavaScript to keep the report self-contained.

### 6.3 Severity Classification

| Severity | Definition |
|---|---|
| Critical | Direct financial impact possible, authentication bypass, BOLA on financial resources, successful race condition |
| High | Security control bypassable but requires additional steps, replay attacks, JWT weaknesses |
| Medium | Defense in depth failure, missing headers, information disclosure |
| Low | Best practice violation with no direct exploitability |
| Info | Observation with no security impact |

---

## 7. Attack Validation Suite

Fracture ships with a validation suite that runs against BrokenCheckout and asserts expected findings. This serves two purposes: it proves the scanner works correctly, and it documents exactly which vulnerabilities BrokenCheckout exposes.

```python
# tests/test_validation.py
async def test_bola_detected():
    results = await run_module("bola", target="brokencheckout")
    assert any(f.cwe_id == "CWE-639" for f in results)
    assert any(f.severity == "critical" for f in results)

async def test_race_condition_detected():
    results = await run_module("race", target="brokencheckout")
    assert any(f.cwe_id == "CWE-362" for f in results)

async def test_webhook_signature_bypass_detected():
    results = await run_module("webhook", target="brokencheckout")
    assert any("signature" in f.title.lower() for f in results)
```

---

## 8. Docker Compose Setup

```yaml
version: "3.9"
services:
  target:
    build: ./target
    ports:
      - "8000:8000"
    volumes:
      - ./target/data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 5s
      timeout: 3s
      retries: 5

  scanner:
    build: ./scanner
    depends_on:
      target:
        condition: service_healthy
    volumes:
      - ./output:/app/output
    environment:
      - TARGET=brokencheckout
    command: python main.py --target brokencheckout --output /app/output
```

One command: `docker compose up`. The target starts, passes its health check, then the scanner runs the full attack suite and writes results to `./output/`.

---

## 9. README Requirements

The README is a first-class deliverable. It must include:

- One-paragraph description of what Fracture is and why it exists
- Architecture diagram showing scanner, target, and output flow
- Screenshot of the HTML report showing findings
- Quick start: `git clone`, `docker compose up`, done
- Vulnerability index table: vulnerability class, CWE ID, severity, affected endpoint in BrokenCheckout
- A section titled "What Fracture Does Not Do" that honestly scopes the tool: it is not a production scanner, it does not handle OAuth flows, it does not test GraphQL APIs. Honest scoping signals engineering maturity.

---

## 10. Implementation Notes for Claude Code

- Use Python 3.11+
- All async code uses `asyncio` and `httpx.AsyncClient`, never `requests`
- All data models use `pydantic` v2
- All database access in BrokenCheckout uses `sqlalchemy` with `aiosqlite`
- Type hints are mandatory on every function signature
- Every module returns `list[Finding]`, never prints directly
- The runner handles all output and logging via `structlog`
- No secrets or credentials hardcoded outside of BrokenCheckout's intentionally insecure auth module
- The scanner must handle connection errors, timeouts, and malformed responses without crashing
- All HTTP requests include a `User-Agent: Fracture/1.0` header
- Concurrency in the race module is configurable via the YAML target config, default 20
