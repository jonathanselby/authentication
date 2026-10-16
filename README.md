# Authentication

[![test](https://github.com/jonathanselby/authentication/actions/workflows/test.yml/badge.svg)](https://github.com/jonathanselby/authentication/actions/workflows/test.yml)

**Verify credentials. Do not become the identity platform.**

`authentication` is a deliberately small Go verification component for applications that need several authentication paths but want enrolment, credential custody, sessions and identity lifecycle to remain elsewhere.

V0.1 verifies five paths: local PBKDF2 password records, RFC 6238 TOTP, pinned-key OIDC ID tokens, pre-registered WebAuthn/passkey assertions, and two-person break-glass credentials. It is independently usable; CRAB is one consumer, not part of the component contract.

## What V0.1 proves

- local password records use PBKDF2-HMAC-SHA256 with a 600,000-iteration minimum, 16-byte minimum salt and 32-byte derived hash;
- TOTP is six digits, SHA-1/RFC 6238 compatible, with a bounded acceptance window and minimum 20-byte secret;
- OIDC is pinned-key verification, not discovery: RS256 signature, exact issuer, primary audience, trusted additional audiences, `azp`, nonce, expiry/not-before and bounded clock skew;
- isolate mode refuses OIDC before token verification;
- passkey verification checks `webauthn.get`, exact encoded challenge and origin, RP ID hash, UP, optionally UV, P-256 signature, and returns the observed signature counter with a warning if it failed to increase;
- break-glass requires exactly two distinct registered keyholders.

See [`PROTOCOLS.md`](PROTOCOLS.md) for the precise subset and deliberate omissions.

## Install

Requires Go 1.26+.

```bash
go install github.com/jonathanselby/authentication/cmd/authcheck@main
authcheck -version
```

Expected version output:

```text
authcheck 0.1.0
```

## CLI

```bash
authcheck -config authentication.json -request attempt.json
```

The configuration holds verification material; the request holds one authentication attempt. Successful and denied attempts are returned as structured JSON.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | authentication succeeded |
| `1` | credentials/method were deterministically denied |
| `2` | invalid CLI usage |
| `3` | malformed configuration/input or execution failure |

Credential failure is not an operational error. `Authenticate` deliberately returns generic denial reasons instead of exposing cryptographic failure detail to the normal caller.

## Security boundary

This component verifies already-enrolled credentials. It does **not** enrol users, generate/store passkeys, perform OIDC discovery/JWKS rotation, issue sessions/cookies/tokens, rate-limit attempts, recover accounts, manage passwords, deliver OTPs, persist WebAuthn counters, or store secrets safely for an application.

The passkey counter is returned to the caller. A non-increasing counter becomes `counter_warning=true`; the consuming application owns persistence and its risk response.

TOTP secrets and password/passkey/OIDC verification records are deployment-owned sensitive configuration. The repository provides no secret store.

## Repository map

```text
authentication/
├── .github/workflows/test.yml
├── PRD.md
├── EDD.md
├── PROTOCOLS.md
├── README.md
├── SKILL.md
├── RELEASE.md
├── VERSION
├── CHANGELOG.md
├── LICENSE
├── architecture.txt
├── go.mod
├── cmd/authcheck/main.go
├── internal/authn/
├── examples/bafflewick/
└── generated/
    ├── EDD.md
    └── COMPARISON.md
```

## Engineering evidence

- [`PRD.md`](PRD.md) — product boundary and acceptance criteria;
- [`EDD.md`](EDD.md) — intended engineering design;
- [`PROTOCOLS.md`](PROTOCOLS.md) — exact verification subsets and security floors;
- [`architecture.txt`](architecture.txt) — trust and runtime boundary;
- [`internal/authn`](internal/authn) — implementation and behavioural tests;
- [`examples/bafflewick`](examples/bafflewick) — executable fictional acceptance case;
- [`generated/EDD.md`](generated/EDD.md) — implementation-derived evidence pinned to a source commit;
- [`generated/COMPARISON.md`](generated/COMPARISON.md) — intended design versus recovered implementation;
- [`RELEASE.md`](RELEASE.md) — release gate.

## Design rule

> **Verify credentials. Do not become the identity platform.**

## Licence

MIT. See [`LICENSE`](LICENSE).
