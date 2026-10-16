# Authentication — Engineering Design Document

**Version:** 0.1

## 1. Purpose

Authentication verifies already-enrolled authentication material for a small application while deliberately leaving identity lifecycle and session state outside the component.

> **Verify credentials. Do not become the identity platform.**

## 2. Design constraints

1. Verification only: no enrolment, issuance, recovery or session management.
2. Local deterministic boundary: no OIDC discovery/JWKS network dependency.
3. Standards before invention: use standard-library cryptography and explicit protocol subsets.
4. Denial is not failure: bad credentials return a structured unauthenticated result; bad configuration/input is an execution error.
5. Security floors are configuration invariants, not caller suggestions.

## 3. Component model

```text
configuration + authentication attempt
                 |
                 v
+----------------------------------+
| cmd/authcheck                    |
| file input / version / exit code |
+----------------+-----------------+
                 |
                 v
+----------------------------------+
| internal/authn                   |
| ValidateConfig -> Authenticate   |
+---+---------+------+-------+-----+
    |         |      |       |
 password   TOTP    OIDC   passkey   breakglass
```

There is no network client or persistent store in the package.

## 4. Configuration model

`Config` may contain local password records, TOTP records, one pinned-key OIDC verifier, passkey records and break-glass records.

`ValidateConfig` checks method-local duplicate user IDs and validates stored verification material before a request is evaluated. A user may legitimately have more than one authentication method; duplicate IDs are prohibited only within the same record set.

OIDC configuration requires issuer, primary audience/client ID and pinned RSA public key. Additional trusted audiences and bounded clock skew are optional.

Passkey configuration holds RP ID, exact origin, P-256 public key, optional UV requirement and last persisted signature counter supplied by the consuming application.

## 5. Authentication result model

`Result` contains:

- `authenticated`;
- subject;
- method;
- two break-glass keyholder IDs where applicable;
- observed passkey signature counter;
- `counter_warning`;
- a generic reason.

Cryptographic verifier functions may return detailed errors for tests/integration, but `Authenticate` maps credential failures to generic denial to avoid exposing verifier detail through the normal application boundary.

## 6. Local password verification

`PBKDF2Record` and `VerifyPassword` use Go 1.26 `crypto/pbkdf2` with HMAC-SHA256.

Security floor:

```text
iterations >= 600000
salt >= 16 bytes
hash = 32 bytes
```

Salt/hash storage is base64. Hash comparison uses `subtle.ConstantTimeCompare`.

The component does not generate salts, choose passwords, rate-limit attempts, use a pepper or store records.

## 7. TOTP verification

TOTP uses a 30-second moving counter and HMAC-SHA1 dynamic truncation compatible with RFC 6238.

Validation requires:

- six decimal digits;
- base32 secret decoding to at least 20 bytes;
- time not before Unix epoch;
- acceptance window from zero to two steps.

Candidate comparison uses constant-time byte comparison.

Replay prevention is outside V0.1 because it requires request/session state.

## 8. OIDC verification

OIDC is deliberately pinned-key rather than discovery based.

`VerifyOIDC`:

1. validates static OIDC configuration;
2. requires a three-part JWT and header algorithm `RS256`;
3. parses payload structure;
4. verifies the JWT signature with the configured RSA public key (minimum 2048 bits);
5. only after signature success evaluates identity claims;
6. requires exact issuer and non-empty subject;
7. requires the configured primary audience;
8. permits additional audiences only when explicitly trusted;
9. requires `azp` for multiple audiences and requires any present `azp` to equal the primary audience/client ID;
10. checks expected nonce when supplied by the caller;
11. checks `exp` and optional `nbf` with configured clock skew bounded to 0..300 seconds.

Isolate mode is evaluated before calling `VerifyOIDC`; no federation network client exists in the component.

## 9. WebAuthn/passkey verification

V0.1 verifies assertions only for already-registered ECDSA P-256 credentials.

`clientDataJSON` validation requires:

- `type == webauthn.get`;
- exact expected challenge string;
- exact configured origin;
- `crossOrigin != true`.

Authenticator-data validation requires:

- at least 37 bytes;
- SHA-256 RP ID hash match;
- User Presence flag;
- User Verification flag when the credential record requires it.

The signature is verified over:

```text
authenticatorData || SHA256(clientDataJSON)
```

using ECDSA P-256/SHA-256.

The observed 32-bit signature counter is returned. If either stored or observed counter is non-zero and the observed value does not increase, the result carries a warning. V0.1 deliberately leaves persistence and risk response to the application.

## 10. Break-glass verification

Break-glass accepts exactly two map entries, therefore two distinct keyholder IDs by construction. Each ID must match a registered break-glass record and each supplied secret must pass the same PBKDF2 record verification used for local authentication.

Returned keyholder IDs are sorted to make output deterministic.

The component does not coordinate two humans or grant application authority; it only verifies the two registered secrets presented together.

## 11. Isolate mode

`Request.IsolateMode` affects only the OIDC path. OIDC returns a deterministic unauthenticated result before token verification.

Local password, TOTP, passkey and break-glass paths are locally verifiable and remain available if configured.

V0.1 has no hidden online dependency, so isolate-mode correctness does not depend on mocking or suppressing a network client.

## 12. Failure and exit semantics

`Authenticate` returns an error for invalid configuration but returns `Authenticated=false` for bad credentials or unsupported authentication methods.

CLI mapping:

| Exit | Meaning |
|---:|---|
| 0 | authentication succeeded |
| 1 | deterministic authentication denial |
| 2 | CLI usage error |
| 3 | malformed configuration/request or execution error |

The CLI validates configuration before authentication.

## 13. Secret and key boundary

This repository consumes verification material; it does not provide a secret store.

Sensitive deployment-owned values can include password hashes/salts, TOTP secrets, break-glass hashes, OIDC public keys and passkey public keys/counters. Public keys are not secret, but their binding to the correct issuer/user/credential is security-sensitive.

V0.1 contains no password plaintext persistence, private asymmetric key custody or outbound secret transmission.

## 14. Testing strategy

Tests use generated ephemeral RSA/P-256 keys and deterministic password/TOTP fixtures.

Coverage includes:

- PBKDF2 success/failure and security floors;
- RFC 6238 six-digit vector, short secret and window/code boundaries;
- pinned OIDC success, multiple audience trust/`azp`, nonce/time bounds and isolate refusal;
- passkey signature, UP/UV, cross-origin refusal and counter warning;
- deterministic two-person break-glass output;
- generic denial semantics;
- configuration rejection.

No live IdP, authenticator or secret store is required for the executable V0.1 evidence.

## 15. Build and dependency boundary

The module targets Go 1.26. Cryptographic primitives use the Go standard library, including `crypto/pbkdf2`, RSA, ECDSA, HMAC/SHA-1 for RFC 6238 and SHA-256.

CI runs format, vet, race tests, native build, exact version assertion, `linux/arm64` cross-build and the Bafflewick authentication suite.

## 16. Known limits

- no enrolment or credential lifecycle;
- no password policy, reset or guess throttling;
- no TOTP replay state;
- no OIDC discovery, JWKS fetch/rotation, OAuth flow or token exchange;
- one pinned OIDC RSA key/config at a time;
- no WebAuthn registration/attestation or authenticator metadata;
- passkey counter state is supplied/persisted by the caller;
- no session/cookie/token issuance;
- no account recovery;
- no constrained-hardware runtime benchmark in V0.1, only ARM64 buildability.

## 17. Acceptance-to-evidence map

| PRD criterion | Executable evidence |
|---|---|
| local password + bad password | `TestLocalAndBreakGlass` |
| PBKDF2 floors | `TestPasswordFloors` |
| RFC 6238 vector/code/window | `TestTOTP` |
| short TOTP secret | `TestTOTPRejectsShortSecret` |
| valid pinned OIDC | `TestOIDC` |
| audience trust + `azp` | `TestOIDCMultipleAudienceRequiresAZPAndTrust` |
| nonce/time bounds | `TestOIDCNonceAndTimeBounds` |
| isolate OIDC denial | `TestIsolateRejectsOIDC` |
| passkey UP+UV/signature/counter | `TestPasskey` |
| required UV | `TestPasskeyRequiresUVWhenConfigured` |
| counter warning + cross-origin refusal | `TestPasskeyCounterWarningAndCrossOriginRefusal` |
| generic denial | `TestAuthenticateReturnsGenericDenial` |
| invalid config | `TestValidateConfig` |
| Go/race/build/ARM64/Bafflewick | `.github/workflows/test.yml` |

`generated/EDD.md` is separately recovered from the source commit and must not be produced by copying this design document.
