# Authentication — Intended vs Recovered Design

**Implementation evidence:** `8938cc829862684f2eb26eb9621973f3374003bc`

This comparison uses the hand-written PRD/EDD as the intended design and `generated/EDD.md` as the implementation-derived view.

| Area | Result | Evidence |
|---|---|---|
| One-job component boundary | MATCH | Core package verifies credentials only; no account/session/enrolment subsystem is present. |
| Go 1.26 baseline | MATCH | `go.mod` declares Go 1.26; CI requests Go 1.26.x. |
| Standard-library cryptography | MATCH | PBKDF2, RSA, ECDSA, HMAC/SHA-1 and SHA-256 are from the Go standard library; no third-party modules are declared. |
| Local-password security floor | MATCH | Source constants require 600,000 iterations, 16-byte salt and 32-byte hash; tests reject weaker records. |
| Six-digit bounded TOTP | MATCH | Source implements 30-second HMAC-SHA1 TOTP, six digits, >=20-byte secret and 0..2 window; reference-vector test exists. |
| Isolate-mode federation cut | MATCH | `Authenticate` refuses OIDC before entering verifier; package contains no network client. |
| Pinned-key OIDC | MATCH | RS256 only, RSA >=2048, signature checked before identity claims; issuer/audience/`azp`/nonce/time rules are executable. |
| WebAuthn assertion verification | MATCH | P-256, `webauthn.get`, challenge/origin/RP hash, UP, optional UV and signature are all verified. |
| Passkey counter handling | MATCH | Counter is returned; non-increase becomes a warning; persistence/risk response remains external. |
| Two-person break-glass credential check | MATCH WITH BOUNDARY | Exactly two distinct keyholder IDs/secrets are required. Code cannot prove two physical humans were present, and design does not claim it can. |
| Generic denial vs execution error | MATCH | Credential failures return unauthenticated results; malformed config/input remains an error/exit 3. |
| Stable CLI/version/exit semantics | MATCH | Thin CLI, explicit version and exit mapping are present. |
| ARM64 portability evidence | MATCH | CI cross-builds `linux/arm64`. |
| Tiny-PC runtime benchmark | DELIBERATE GAP | No runtime benchmark exists in V0.1; only buildability is claimed. |
| OIDC discovery/JWKS rotation | DELIBERATE GAP | Explicitly excluded; source has no network/discovery client. |
| Session/account lifecycle | DELIBERATE GAP | Explicitly excluded and absent from source. |
| TOTP replay/rate limiting | DELIBERATE GAP | Requires external state; absent by design. |
| WebAuthn registration/attestation | DELIBERATE GAP | V0.1 verifies pre-registered assertions only. |
| External secret/key custody | UNKNOWN | Repository does not implement or prove deployment storage controls. |
| Production operational controls | UNKNOWN | Monitoring, lockout, recovery, rotation, audit and session policy belong to consumers. |

## Acceptance traceability

Every V0.1 PRD criterion has named executable evidence in `internal/authn/authn_test.go` or the CI workflow. The recovered design independently finds the same major boundaries rather than revealing a hidden second identity system.

## Material differences

No material mismatch was found between the intended V0.1 design and the source commit analysed.

The important qualifications are boundary qualifications, not implementation defects:

1. “two-person break-glass” means two distinct registered keyholder credentials in one request; the component cannot establish physical human presence;
2. passkey counter anomalies are surfaced but not persisted or adjudicated;
3. pinned-key OIDC avoids a network dependency but leaves key rotation/discovery to deployment;
4. ARM64 is a build proof, not a constrained-hardware performance benchmark.

## Conclusion

**MATCH for V0.1.** The implementation is narrower than a full identity service in exactly the places the design says it should be. The recovered evidence supports the repository's core claim: verify credentials without absorbing identity-platform responsibilities.
