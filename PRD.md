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
- separation of credential input from trusted ceremony state;
- configuration validation and security bounds;
- generic authentication-denial result;
- stable CLI/exit codes;
- Go 1.26 and `linux/arm64` build proof.

## 5. Out of scope

Enrolment/registration, account database, password change/reset/policy, random salt/secret generation, OIDC discovery or JWKS rotation, OAuth flows, sessions/cookies/token issuance, rate limiting, MFA orchestration, TOTP replay storage, WebAuthn attestation/registration, credential persistence, passkey counter persistence, account recovery and secret/key custody.

## 6. Functional requirements

### FR1 — Configuration before verification
Malformed or out-of-bound verification records are rejected as configuration errors before an authentication decision.

### FR2 — Local password bounds
PBKDF2-HMAC-SHA256 records require 600,000 through 2,000,000 iterations, a 16-byte salt and a 32-byte derived hash. Verification comparison is constant time. Unknown local user IDs must not take an obvious no-password-work fast path.

### FR3 — TOTP boundary
TOTP accepts exactly six decimal digits, a decoded secret of at least 20 bytes, 30-second steps and a configured window from zero through two steps.

### FR4 — Trusted ceremony boundary
Current time, expected OIDC nonce, expected WebAuthn challenge and isolate-mode state are supplied through a trusted context separate from credential request JSON.

### FR5 — Isolate mode
OIDC is deterministically denied in isolate mode before token verification. This component has no federation discovery/network dependency.

### FR6 — Pinned-key OIDC
OIDC validates RS256 signature using a pinned RSA >=2048-bit key before trusting claims, then checks issuer, subject, audience trust, `azp`, optional expected nonce, expiry, optional not-before and bounded clock skew.

### FR7 — Passkey assertion
Passkey verification checks client data, trusted expected challenge, origin, RP ID hash, UP, optional required UV, P-256 signature and the observed authenticator signature counter.

### FR8 — Counter visibility
A non-increasing WebAuthn signature counter is surfaced as a warning rather than silently ignored or treated as definitive proof of compromise.

### FR9 — Break-glass
Break-glass configuration rejects duplicate keyholder IDs and authentication succeeds only when exactly two distinct registered keyholder credentials verify in the same request.

### FR10 — Denial vs execution failure
Bad credentials and unsupported authentication methods return deterministic unauthenticated results. Invalid configuration/input files or process failures remain execution errors.

## 7. Acceptance criteria

V0.1 is accepted when automated evidence shows:

1. correct local password verifies and incorrect or unknown user credentials are denied generically;
2. PBKDF2 work factors outside the supported bounds and short salts are rejected;
3. RFC 6238 six-digit vector passes;
4. non-numeric TOTP, excessive window and short secret are rejected;
5. isolate mode denies OIDC;
6. valid pinned-key OIDC succeeds;
7. multiple OIDC audiences require correct `azp` and explicit trust for every additional audience;
8. nonce and time bounds are enforced from trusted ceremony state;
9. passkey assertion with trusted challenge, UP+required UV and correct signature succeeds;
10. missing required UV, wrong challenge and cross-origin assertion are rejected;
11. non-increasing passkey counter produces a warning;
12. duplicate break-glass configuration is rejected and exactly two valid keyholders succeed deterministically;
13. bad credentials and unsupported methods produce denial, not execution errors;
14. invalid configuration is rejected;
15. format, vet, race tests, native build, version and `linux/arm64` build pass in CI.

## 8. Definition of done

V0.1 is done when all acceptance criteria have executable evidence, the supported authentication subsets and trusted ceremony boundary are documented precisely, known lifecycle/state omissions are explicit, Go 1.26 CI is green, and a generated EDD independently recovers the release-candidate implementation.
