# 0001: JWT and SD-JWT crate selection

**Status:** Accepted
**Date:** 2026-09-04

## Context

`ap2-credentials` needs two layers of credential mechanics:

1. Plain compact JWT/JWS parsing and signature verification, used for the
   merchant-signed `checkout_jwt`.
2. SD-JWT (RFC 9901) parsing, selective-disclosure digest verification, and
   key-binding (KB-JWT) verification, used for the Checkout/Payment Mandate
   wrapper itself.

Per the project's engineering principles, we implement AP2 *semantics*, not
cryptographic primitives: no hand-rolled SHA-2, ECDSA, or base64url. The
question this ADR answers is which existing crates to build on.

## Decision

- **JWT/JWS: [`jsonwebtoken`](https://github.com/Keats/jsonwebtoken) (Keats), v11.x, MIT.**
- **SD-JWT: [`sd-jwt-payload`](https://github.com/iotaledger/sd-jwt-payload) (IOTA Foundation), v0.5.x, Apache-2.0.**

## Rationale

### `jsonwebtoken`

- MIT license, compatible with our `deny.toml` allow-list.
- By far the most widely used JWT crate in the Rust ecosystem (~181M total
  downloads, ~45M in the last 90 days as of this writing), actively
  maintained (last push within weeks of this ADR).
- Its `Validation` struct takes an explicit algorithm allow-list. This is
  the exact mechanism needed to enforce the spec's requirement that Checkout
  JWTs be signed with a randomized scheme (e.g. ECDSA/ES256) and never a
  deterministic one (Ed25519) — we can reject the latter outright rather
  than trusting whatever algorithm the token header claims.

### `sd-jwt-payload` over `affinidi-sd-jwt`

Two credible SD-JWT crates were evaluated:

| | `sd-jwt-payload` | `affinidi-sd-jwt` |
|---|---|---|
| License | Apache-2.0 | Apache-2.0 |
| Backing | IOTA Foundation | Affinidi (part of a larger monorepo) |
| Created | 2023-10 | 2026-03 |
| Documentation | Full README with worked examples | None found on crates.io or in-repo |
| Key-binding support | Explicit: `RequiredKeyBinding`, `KeyBindingJwtBuilder`, `cnf`/`kid` requirement on the builder | Unable to verify |

`affinidi-sd-jwt` is pushed more frequently as of this writing, but recency
of commits is not itself a trust signal for a security-critical dependency.
`sd-jwt-payload` directly and demonstrably supports what AP2's autonomous
flow requires: an open mandate's `cnf` claim referencing an agent key, and
a closed mandate presented with an attached KB-JWT proving possession of
that key. That is shown working in its README (decoys, concealment, digest
verification, and key-binding requirement enforcement) — `affinidi-sd-jwt`
could not be evaluated on the same criteria due to lack of documentation.

## Caveat

Neither crate is anywhere near as battle-tested as `ring` or `rustls`.
"We implement AP2 semantics, not crypto primitives" does not mean
`sd-jwt-payload`'s actual behavior can be trusted without verification.
`ap2-credentials`'s test suite must include real RFC 9901 test vectors, not
only our own round-trip tests, before either crate is trusted in the
verification path.

## Consequences

- `ap2-credentials/Cargo.toml` will depend on `jsonwebtoken` and
  `sd-jwt-payload` at pinned versions.
- If `sd-jwt-payload` proves to lack a required RFC 9901 feature (or its
  maintenance lapses), this ADR should be revisited rather than patched
  around silently.
