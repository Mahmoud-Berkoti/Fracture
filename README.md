# Fracture

Payment API security testing framework. Surfaces vulnerability classes endemic to fintech infrastructure — BOLA, race conditions, JWT bypass, business-logic flaws, webhook signature failures — that generic API scanners systematically miss.

Ships as two components: **BrokenCheckout** (a deliberately-vulnerable target API) and the **Fracture scanner** (the attack suite). One command (`docker compose up`) runs everything.

See [`FRACTURE_SPEC.md`](FRACTURE_SPEC.md) for the full technical specification.

> Project under active construction.
