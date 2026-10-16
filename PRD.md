# Authentication — Product Requirements Document

**Version:** 0.1

## 1. Problem

Small operational applications may need local, federated, passkey and emergency authentication without embedding a complete identity platform. Pulling enrolment, sessions, credential lifecycle, remote federation discovery and recovery logic into every application would create unnecessary state and security surface.

## 2. Product objective

Provide a small Go component that verifies already-enrolled authentication material through several explicit paths while leaving identity lifecycle and session management outside the component.

> **Verify credentials. Do not become the identity platform.**

## 3. Users

Engineers building self-hosted or occasionally isolated applications that need a deterministic authentication verification boundary.

## 4. In scope

- PBKDF2-HMAC-SHA256 local password verification;
- six-digit RFC 6238 TOTP verification;
- pinned-key RS256 OIDC ID-token verification;
- pre-registered ECDSA P-256 WebAuthn assertion verification;
- two-person break-glass credential verification;
- isolate-mode OIDC refusal;
- configuration validation and security floors;
- generic authentication-denial result;
- stable CLI/exit codes;
- Go 1.26 and `linux/arm64` build proof.

## 5. Out of scope

Enrolment/registration, account database, password change/reset/policy, random salt/secret generation, OIDC discovery or JWKS rotation, OAuth flows, sessions/cookies/token issuance, rate limiting, MFA orchestration, TOTP replay storage, WebAuthn attestation/registration, credential persistence, passkey counter persistence, account recovery and secret/key custody.

## 6. Functional requirements

### FR1 — Configuration before verification
Malformed or below-floor verification records are rejected as configuration errors before an authentication decision.

### FR2 — Local password floor
PBKDF2-HMAC-SHA256 records require at least 600,000 iterations, a 16-byte salt and a 32-byte derived hash. Verification comparison is constant time.

### FR3 — TOTP boundary
TOTP accepts exactly six decimal digits, a decoded secret of at least 20 bytes, 30-second steps and a configured window from zero through two steps.

### FR4 — Isolate mode
OIDC is deterministically denied in isolate mode before token verification. This component has no federation discovery/network dependency.

### FR5 — Pinned-key OIDC
OIDC validates RS256 signature using a pinned RSA >=2048-bit key before trusting claims, then checks issuer, subject, audience trust, `azp`, optional expected nonce, expiry, optional not-before and bounded clock skew.

### FR6 — Passkey assertion
Passkey verification checks client data, origin/challenge, RP ID hash, UP, optional required UV, P-256 signature and the observed authenticator signature counter.

### FR7 — Counter visibility
A non-increasing WebAuthn signature counter is surfaced as a warning rather than silently ignored or treated as definitive proof of compromise.

### FR8 — Break-glass
Break-glass succeeds only when exactly two distinct registered keyholder credentials verify in the same request.

### FR9 — Denial vs execution failure
Bad credentials and unsupported authentication methods return deterministic unauthenticated results. Invalid configuration/input files or process failures remain execution errors.

## 7. Acceptance criteria

V0.1 is accepted when automated evidence shows:

1. correct local password verifies and incorrect password is denied;
2. weak PBKDF2 work factor and short salt are rejected;
3. RFC 6238 six-digit vector passes;
4. non-numeric TOTP, excessive window and short secret are rejected;
5. isolate mode denies OIDC;
6. valid pinned-key OIDC succeeds;
7. multiple OIDC audiences require correct `azp` and explicit trust for every additional audience;
8. nonce and time bounds are enforced;
9. passkey assertion with UP+required UV and correct signature succeeds;
10. missing required UV and cross-origin assertion are rejected;
11. non-increasing passkey counter produces a warning;
12. exactly two valid break-glass keyholders succeed and output is deterministic;
13. bad credentials and unsupported methods produce denial, not execution errors;
14. invalid configuration is rejected;
15. format, vet, race tests, native build, version and `linux/arm64` build pass in CI.

## 8. Definition of done

V0.1 is done when all acceptance criteria have executable evidence, the supported authentication subsets are documented precisely, known lifecycle/state omissions are explicit, Go 1.26 CI is green, and a generated EDD independently recovers the release-candidate implementation.
