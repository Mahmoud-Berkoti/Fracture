# Fracture - Threat Model

Fracture is built to surface the vulnerability classes that actually matter
in payment APIs - the ones general-purpose web scanners systematically miss
because they require either (a) cross-user reasoning, (b) true concurrent
HTTP dispatch within a millisecond window, or (c) understanding of the
business domain the API operates in.

This document specifies the threats Fracture detects, the detection
signals it relies on, and the threats it explicitly does **not** cover.

---

## In scope

### T1. Broken Object Level Authorization (BOLA / IDOR)

Resource identifiers exposed in URLs (`/v1/payment-methods/{id}`,
`/v1/invoices/{id}`, `/v1/customers/{id}/...`) without per-request
ownership enforcement. Detection: authenticate as User A, observe a
resource id; authenticate as User B, request that id; HTTP 200 with a
non-empty body is the signal.

**Attacker capability:** any authenticated user (the lowest privilege
tier on the platform).

**Impact:** read/modify/delete other users' financial resources.

### T2. Race conditions in transaction endpoints

Check-then-act handlers (refunds, coupon redemption, balance debits,
subscription mutations) without row-level locking, idempotency-key
enforcement, or guarded UPDATE patterns. Detection: dispatch N
concurrent HTTP requests within the same event-loop tick (`asyncio.gather`
on `httpx.AsyncClient` coroutines) and count >1 successful responses
for an operation that should succeed at most once.

**Attacker capability:** any authenticated user with a fast network
link.

**Impact:** double-refund / coupon reuse / double-spend / subscription
billing-state corruption - direct financial loss.

### T3. JWT authentication bypass

- `alg:none` acceptance (CWE-347)
- Weak/guessable signing secret (CWE-798) - tested against a 13-entry
  common-secret wordlist
- `exp` claim not validated (CWE-613)

**Attacker capability:** any internet host that can craft an HTTP
request - no prior credentials required if `alg:none` works.

**Impact:** authentication as any user; perpetual token validity.

### T4. Business-logic flaws in financial operations

- Negative amount accepted (effective credit to attacker)
- Zero amount accepted (audit-log pollution, oracle abuse)
- INT64-near amount accepted (overflow / aggregation corruption)
- Arbitrary currency code accepted (FX-pricing bypass)

**Attacker capability:** any authenticated user.

**Impact:** direct treasury drain (negative), reporting integrity loss
(overflow), pricing manipulation (currency confusion).

### T5. Webhook security

- Missing signature header still processed (CWE-345)
- Replay outside tolerance window accepted (CWE-294)

**Attacker capability:** any internet host that can reach the webhook
endpoint. For replay: any host that has previously observed (or can
observe) one legitimate signed event.

**Impact:** inject arbitrary payment-state transitions into the
application; cause an observed event to fire repeatedly.

---

## Detection signals

| Class | Primary signal | Secondary signal |
|---|---|---|
| BOLA | HTTP 200 to attacker request | Response body contains victim-owned data |
| Race | >1 of N concurrent requests return 2xx | Single-use resource consumed multiple times |
| Auth | HTTP 200 to forged-token request | Response body matches victim's legitimate session |
| Business logic | HTTP 2xx to malformed payload | Persisted record reflects malicious values |
| Webhook | HTTP 2xx with missing/expired signature | Event recorded in target's storage |

---

## Explicitly out of scope

Fracture is purpose-built. It does **not** test:

- **SQL injection** - covered by generic scanners (sqlmap, Burp).
- **XSS / CSRF** - JSON-API-focused; no HTML response surface tested.
- **OAuth 2.0 / OIDC flows** - JWT bearer-token only.
- **GraphQL APIs** - REST-only path templates.
- **Rate limiting / DoS** - Fracture's concurrent dispatch is for race
  detection, not load generation. Defaults to N=20.
- **Mass-targeting** - single-target per invocation by design.
- **Production exploitation** - scanner is for authorized test
  environments only. Honest scoping: see `README.md` § "What Fracture
  Does Not Do".

---

## Trust boundaries

Fracture treats the scanner and target as separate trust domains
joined by HTTP over a Docker bridge network. The scanner has the same
privileges as any external caller with valid credentials from the YAML
config - no in-process access to the target, no shared filesystem
beyond the `./output` mount. This deliberately mirrors a real
black/grey-box engagement.

---

## Attacker model assumptions

The scanner models an authenticated user with internet-grade network
access and the ability to send concurrent requests (≥20 in-flight).
For webhook tests, the attacker has unauthenticated access to the
webhook endpoint and optionally has previously observed one
legitimate event with its signature.

The scanner does **not** model:
- A privileged insider with database access
- An attacker who controls the TLS certificate chain
- An attacker with side-channel access (timing, power, error-message
  oracles beyond response status)
