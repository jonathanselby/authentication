# Authentication — Engineering Design Document

**Version:** 0.1  
**Reviewed:** 2026-10-22

## 1. Purpose

Authentication verifies already-enrolled credentials without becoming an identity platform.

> **Verify credentials. Keep ceremony state outside untrusted requests.**

The component remains local and deterministic: no identity database, session store, OIDC discovery or outbound network dependency.

## 2. Trust boundary

Authentication has three inputs:

1. `Config` — registered verification material and static policy;
2. `Request` — credentials presented by the claimant;
3. `TrustedContext` — ceremony state supplied by the integrating application.

`Request` contains method, user ID and the presented password/TOTP/OIDC token/passkey assertion/break-glass secrets. It cannot supply current time, expected OIDC nonce, expected WebAuthn challenge or isolate-mode state.

`TrustedContext` carries those four security-sensitive values. If `Now` is zero, `Authenticate` uses the process UTC clock. This is deliberately not a session store: challenge/nonce generation and persistence remain outside this component.

## 3. Configuration validation

`ValidateConfig` runs before authentication. It validates stored password/TOTP/OIDC/passkey/break-glass material and rejects duplicate records within each authentication method. A person may still have multiple different authentication methods.

Break-glass duplicate keyholder IDs are rejected at configuration time as well as by the verifier.

## 4. Local passwords

PBKDF2-HMAC-SHA256 uses:

```text
600000 <= iterations <= 2000000
salt >= 16 bytes
hash = 32 bytes
```

The upper bound prevents hostile or corrupt configuration from causing unbounded CPU work. Stored hash comparison is constant time.

For an unknown local user, authentication performs one valid minimum-cost dummy PBKDF2 check before returning the same generic denial. This removes the obvious zero-work username path; application-level rate limiting remains out of scope.

## 5. TOTP

TOTP is six decimal digits, HMAC-SHA1 dynamic truncation, 30-second steps and a configurable window of 0..2. Secrets must decode to at least 20 bytes.

Time comes from `TrustedContext` or the system clock, never credential request JSON.

## 6. Pinned-key OIDC

OIDC remains deliberately small: RS256 only, pinned RSA public key >=2048 bits, no discovery/JWKS network client.

After signature verification it checks exact issuer, non-empty subject, configured audience, trusted additional audiences, `azp` rules, optional expected nonce, expiry and optional `nbf` with bounded clock skew.

Expected nonce, current time and isolate-mode state come from `TrustedContext`. Isolate mode denies OIDC before token verification.

## 7. Passkeys

V0.1 verifies assertions for registered ECDSA P-256 credentials.

`VerifyPasskey` receives the expected challenge separately from the assertion. It checks:

- `type == webauthn.get`;
- client-data challenge equals the trusted expected challenge;
- exact configured origin and no cross-origin assertion;
- RP ID hash;
- User Presence and optional User Verification flags;
- ECDSA P-256 signature over `authenticatorData || SHA256(clientDataJSON)`.

The assertion can no longer nominate the value against which its own challenge is accepted.

The observed signature counter is returned. A non-increasing non-zero counter remains a warning rather than an automatic rejection because counter persistence/risk policy belongs to the relying application.

## 8. Break-glass

Exactly two distinct registered keyholder credentials must verify together. Their password records use the same bounded PBKDF2 rules as local authentication. Returned IDs are sorted for deterministic output.

The component verifies credentials only; it does not grant emergency authority or coordinate the two humans.

## 9. CLI boundary

`authcheck` reads configuration and credential request JSON from files. Trusted ceremony values are separate CLI inputs:

```text
-oidc-nonce
-passkey-challenge
-isolate
```

Authentication time is taken from the process clock. No request-file `now`, nonce, challenge or isolate flag is trusted.

Exit codes remain:

| Exit | Meaning |
|---:|---|
| 0 | authentication succeeded |
| 1 | authentication denied |
| 2 | CLI usage error |
| 3 | configuration/input/execution error |

## 10. Tests and evidence

Automated tests cover password lower/upper bounds, known/unknown-user generic denial, TOTP boundaries, pinned OIDC claims and trusted context, passkey challenge/UP/UV/origin/signature/counter behaviour, duplicate break-glass configuration and deterministic break-glass output.

CI remains authoritative for this Go 1.26 module and runs `gofmt`, `go vet`, race tests, native build, version contract, `linux/arm64` build and the Bafflewick acceptance subset.

## 11. Deliberate limits

V0.1 still does not implement enrolment, password policy/reset, rate limiting, TOTP replay storage, OIDC discovery/JWKS rotation, OAuth flows, WebAuthn registration/attestation, credential persistence, passkey counter persistence, sessions, account recovery or key custody.

These omissions are boundaries, not invitations to recreate an identity platform inside this component.
