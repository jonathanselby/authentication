# Authentication — Recovered Engineering Design

**Evidence commit:** `8938cc829862684f2eb26eb9621973f3374003bc`  
**Recovery method:** source, tests, CLI and CI inspection  
**Classification:** KNOWN / INFERRED / UNKNOWN

## 1. Observed purpose

**KNOWN.** The repository is a verification-only authentication component. `internal/authn.Authenticate` supports five methods: `local`, `totp`, `oidc`, `passkey` and `breakglass`. The package contains no enrolment API, session store, HTTP server, database driver or outbound network client.

**INFERRED.** The intended architectural role is a narrow trust boundary that consumes deployment-owned verification material and returns an authentication decision without taking ownership of identity lifecycle.

## 2. Runtime shape

**KNOWN.** `cmd/authcheck/main.go` is a thin file-based CLI. It reads one configuration JSON document and one request JSON document, calls `ValidateConfig`, then calls `Authenticate`, emits one JSON result and maps outcome classes to process exit codes.

**KNOWN.** The core implementation is in `internal/authn/authn.go`; executable behavioural evidence is in `internal/authn/authn_test.go`.

## 3. Configuration state

**KNOWN.** `Config` may hold:

- `[]PasswordRecord`;
- `[]TOTPRecord`;
- one optional `*OIDCConfig`;
- `[]PasskeyRecord`;
- `[]BreakGlassRecord`.

**KNOWN.** The package itself persists none of these records. They are caller-supplied values.

**KNOWN.** `ValidateConfig` validates each configured method before an authentication attempt. Duplicate user IDs are rejected within local, TOTP and passkey method sets. Break-glass records are validated as password records.

## 4. Local-password path

**KNOWN.** `PBKDF2Record` and `VerifyPassword` use Go `crypto/pbkdf2` with SHA-256. Constants enforce:

```text
MinPBKDF2Iterations = 600000
MinSaltBytes        = 16
PasswordHashBytes   = 32
```

**KNOWN.** Stored salt and hash fields are standard base64. Password comparison uses `subtle.ConstantTimeCompare`.

**UNKNOWN.** Salt generation, password policy, guess throttling, peppers and storage protection are not implemented here and therefore cannot be inferred from this repository.

## 5. TOTP path

**KNOWN.** `VerifyTOTP` accepts exactly six decimal digits, validates a configured window in the range 0..2, decodes base32 secrets without padding and requires at least 20 decoded bytes.

**KNOWN.** TOTP uses a 30-second Unix counter, HMAC-SHA1 dynamic truncation and modulo 1,000,000. `TestTOTP` checks the six-digit RFC-style vector `287082` at Unix time 59 seconds.

**KNOWN.** Candidate comparison is constant-time.

**UNKNOWN.** Replay prevention and attempt throttling are absent because the package has no request history or session state.

## 6. OIDC path

**KNOWN.** OIDC is local pinned-key verification. There is no discovery/JWKS fetch path in the code.

**KNOWN.** `VerifyOIDC` accepts only JWT header `alg=RS256`, parses the token, then verifies its RSA signature before claim values are used for an identity decision. `parseRSA` requires a public key of at least 2048 bits.

**KNOWN.** Claim checks include:

- exact configured issuer;
- non-empty subject;
- non-zero expiry;
- presence of the configured primary audience;
- explicit trust for every additional audience;
- mandatory `azp` for multiple audiences;
- any present `azp` equals the primary configured audience/client ID;
- expected nonce when supplied;
- `exp` and optional `nbf` with configured clock skew.

**KNOWN.** Configured clock skew is bounded to 0..300 seconds.

**KNOWN.** `Authenticate` checks `IsolateMode` before entering `VerifyOIDC` and returns a deterministic denial.

**UNKNOWN.** Provider discovery, key rotation, OAuth flow correctness and remote issuer availability are outside this codebase.

## 7. Passkey path

**KNOWN.** V0.1 verifies pre-registered ECDSA P-256 assertions. `parseECDSA` refuses other key types/curves.

**KNOWN.** `VerifyPasskey` decodes `clientDataJSON`, requires `type=webauthn.get`, exact caller-supplied challenge, exact configured origin and rejects `crossOrigin=true`.

**KNOWN.** Authenticator data must be at least 37 bytes. The first 32 bytes must equal SHA-256 of the configured RP ID. User Presence is always required; User Verification is required when the stored record requests it.

**KNOWN.** The ECDSA signature is checked over `authenticatorData || SHA256(clientDataJSON)` using SHA-256.

**KNOWN.** The observed signature counter is returned. If either stored or observed count is non-zero and the observed count fails to increase, `CounterWarning` is true rather than authentication automatically failing.

**UNKNOWN.** Registration, attestation, credential persistence, authenticator metadata and the application's response to a counter warning are outside this repository.

## 8. Break-glass path

**KNOWN.** `VerifyBreakGlass` requires `len(keys) == 2`. Since the request representation is a Go map keyed by user ID, the two presented entries necessarily have distinct IDs.

**KNOWN.** Each ID must exist in configured break-glass records and each secret is verified using the password-record PBKDF2 path. Successful keyholder IDs are sorted before return, making output deterministic.

**INFERRED.** The component proves simultaneous presentation of two registered secrets; it does not prove two humans were physically present.

## 9. Authentication result and denial semantics

**KNOWN.** `Result` exposes `Authenticated`, `Subject`, `Method`, optional break-glass `Keyholders`, passkey `SignCount`, `CounterWarning` and `Reason`.

**KNOWN.** Invalid credentials on supported methods are mapped by `Authenticate` to generic `credentials rejected` denial rather than returning cryptographic verifier errors to the normal application caller.

**KNOWN.** Unsupported methods are also deterministic unauthenticated results.

**KNOWN.** Invalid configuration remains an error.

## 10. CLI contract

**KNOWN.** `authcheck -version` prints `authcheck 0.1.0`.

**KNOWN.** CLI exits are:

```text
0 authenticated
1 deterministic authentication denial
2 CLI usage error
3 configuration/input/execution error
```

**KNOWN.** Configuration is validated before `Authenticate` is called.

## 11. Dependencies and network boundary

**KNOWN.** `go.mod` declares only the module and Go 1.26; no third-party modules are declared.

**KNOWN.** Cryptography comes from the Go standard library, including `crypto/pbkdf2`, RSA, ECDSA, HMAC/SHA-1 and SHA-256.

**KNOWN.** No HTTP client, DNS call, socket, database or filesystem persistence exists in `internal/authn`; the CLI reads only its two input files.

## 12. Security properties evidenced by tests

**KNOWN.** Named tests cover:

- local password success/failure and PBKDF2 floors;
- TOTP reference vector, numeric format, secret length and window bound;
- valid pinned OIDC;
- additional audience trust, `azp`, nonce and time bounds;
- isolate-mode federation denial;
- passkey signature, UP/UV, cross-origin denial and counter warning;
- two-keyholder break-glass;
- generic denial and configuration refusal.

**KNOWN.** RSA and P-256 keys used by tests are generated ephemerally in memory.

## 13. CI and build evidence

**KNOWN.** `.github/workflows/test.yml` targets Go 1.26.x and requires:

- no `gofmt` differences;
- `go vet ./...`;
- `go test -race -count=1 ./...`;
- native CLI build;
- exact CLI version assertion;
- `GOOS=linux GOARCH=arm64` build;
- named Bafflewick authentication acceptance tests.

**INFERRED.** This demonstrates portability/buildability for Linux ARM64, not runtime performance on a constrained device.

## 14. Failure model

**KNOWN.** Verification functions return errors for malformed protocol/configuration material. `Authenticate` intentionally absorbs credential-verification failures into generic denials.

**KNOWN.** CLI file read, JSON parse, configuration-validation or unexpected `Authenticate` errors map to exit 3.

**UNKNOWN.** Operational logging, monitoring, lockout, alerting and audit retention are external concerns.

## 15. Concurrency and state

**KNOWN.** Core verification functions mutate no package-global state. Configuration and requests are passed by value/reference for a single call.

**INFERRED.** The package can be called concurrently so long as callers do not concurrently mutate shared input objects.

**UNKNOWN.** End-to-end concurrency/session behaviour depends on the consuming application.

## 16. Observed limits

**KNOWN.** V0.1 does not implement enrolment, account lifecycle, password reset/policy, salt generation, rate limiting, TOTP replay state, OIDC discovery/JWKS rotation, OAuth flows, sessions, WebAuthn registration/attestation, passkey counter persistence, account recovery or secret/key custody.

**KNOWN.** OIDC configuration holds one pinned verifier key/config at a time.

**KNOWN.** The repository proves ARM64 compilation, not a tiny-PC runtime benchmark.

## 17. Evidence conclusion

**KNOWN.** The source at `8938cc829862684f2eb26eb9621973f3374003bc` implements a small, stateless credential-verification boundary with explicit security floors and method-specific validation rather than a general identity platform.

**INFERRED.** Its strongest reusable property is the separation of verification from enrolment/session/account state, which keeps the component testable and suitable for self-hosted or isolated applications.

**UNKNOWN.** Production fitness still depends on the surrounding application's credential storage, rate limiting, session issuance, audit, recovery, key rotation and operational controls.
