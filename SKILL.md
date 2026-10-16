# Authentication — Skill

## Use this when

Use `authentication` when an application needs to verify already-enrolled local, TOTP, pinned OIDC, passkey or two-person break-glass credentials without acquiring identity-platform responsibilities.

## Core rule

> **Verify credentials. Do not become the identity platform.**

## Read order

1. `PRD.md` — product boundary and acceptance criteria.
2. `PROTOCOLS.md` — exact algorithms/protocol subsets and security floors.
3. `EDD.md` — runtime, trust and failure design.
4. `architecture.txt` — compact boundary.
5. `examples/bafflewick/` — executable acceptance evidence.

## Change discipline

1. Run format, vet and race tests before/after changes.
2. Do not add enrolment, session or account lifecycle state here.
3. Prefer Go standard-library cryptography over custom primitives.
4. Treat security-floor changes as externally visible behaviour.
5. Keep isolate mode independent of federation discovery/network access.
6. Verify OIDC signatures before using claims for identity decisions.
7. Do not silently ignore WebAuthn counter anomalies; expose them to the caller.
8. Keep bad credentials as deterministic denial, not operational failure.
9. Regenerate code-derived evidence after code changes.
10. Do not tag until `RELEASE.md` is satisfied.

## Do not use this repo for

Credential enrolment/storage, IdP discovery/JWKS lifecycle, OAuth/session issuance, account recovery, rate limiting, OTP delivery/replay state, passkey registration/attestation, or secret/key custody.
