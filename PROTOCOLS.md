# Authentication — Verification Protocol Boundary

**Component version:** 0.1.0  
**Reviewed:** 2026-10-17

This file defines what the component verifies and, equally importantly, what it deliberately leaves to the surrounding identity/application platform.

## Local password records

V0.1 supports PBKDF2-HMAC-SHA256 only.

Security floor:

```text
iterations >= 600000
salt length >= 16 bytes
derived hash = 32 bytes
```

Go 1.26 `crypto/pbkdf2` performs derivation. Stored hashes and comparisons use base64 plus constant-time comparison. The component verifies records; it does not generate random salts, change passwords, enforce password policy, rate-limit guesses or store a pepper.

## TOTP

V0.1 implements six-digit HOTP truncation over HMAC-SHA1 with a 30-second TOTP step. The RFC 6238 SHA-1 reference secret produces six-digit `287082` at Unix time 59 seconds.

Security floor:

```text
base32 secret decodes to >= 20 bytes
code is exactly six decimal digits
window is 0..2 steps
```

The component does not provision QR codes, deliver secrets, prevent replay across requests or rate-limit guesses. Those need application/session state.

## OIDC ID token verification

V0.1 is deliberately **pinned-key** OIDC verification. It does not perform provider discovery or JWKS retrieval.

Supported JWT algorithm: `RS256` with a pinned RSA public key of at least 2048 bits.

Validated claims:

- exact `iss`;
- non-empty `sub`;
- configured primary audience is present;
- every additional audience must be explicitly trusted in configuration;
- multiple audiences require `azp`, and any present `azp` must equal the configured primary audience/client ID;
- non-zero `exp` with optional bounded clock skew;
- `nbf` when present;
- `nonce` when the caller supplies an expected nonce.

The signature is verified before claim values are used for an identity decision.

`clock_skew_seconds` is bounded to 0..300. Isolate mode denies OIDC before token verification and makes no discovery/network call because none exists in this component.

## WebAuthn / passkey assertion verification

V0.1 verifies assertions for already-registered ECDSA P-256 credentials.

The caller supplies the expected WebAuthn challenge string exactly as it should appear in `clientDataJSON.challenge` (normally base64url encoding of the random challenge bytes).

Validation includes:

- `type == "webauthn.get"`;
- exact challenge;
- exact origin;
- `crossOrigin` must not be true;
- SHA-256 RP ID hash;
- User Presence (UP) flag;
- User Verification (UV) flag when the stored credential record requires it;
- ECDSA P-256 signature over `authenticatorData || SHA256(clientDataJSON)`.

The observed signature counter is returned. If either the stored or observed counter is non-zero and the new counter does not increase, the result carries `counter_warning=true`; V0.1 does not itself reject or persist the counter because clone-risk response belongs to the relying application.

The component does not implement WebAuthn registration, attestation validation, credential storage, origin policy management, backup-state policy or authenticator metadata services.

## Break-glass

Break-glass requires exactly two distinct registered keyholder IDs in one attempt. Each supplied secret is verified against its own PBKDF2 record using the same password security floor.

The component does not coordinate two humans, deliver challenges, schedule emergency windows or override application authorisation. It only proves that two registered break-glass credentials were supplied together.

## Upgrade rule

A change to an algorithm, security floor, OIDC claim contract, WebAuthn ceremony or authentication result semantics requires tests, PRD/EDD update, regenerated code-derived evidence and a new release version when externally observable behaviour changes.
