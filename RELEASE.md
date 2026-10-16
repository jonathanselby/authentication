# Release checklist

## Source and version

- [ ] `VERSION`, CLI version and release tag agree.
- [ ] `go.mod` uses the Garage Go baseline.
- [ ] `CHANGELOG.md` records the release.

## Security/protocol gate

- [ ] password/TOTP/OIDC/WebAuthn floors match `PROTOCOLS.md`.
- [ ] no custom password-KDF implementation has replaced Go standard-library PBKDF2.
- [ ] OIDC verification remains pinned-key and signature precedes identity decision.
- [ ] passkey UP/UV/counter semantics remain explicit.
- [ ] isolate mode contains no federation network dependency.

## Engineering gate

- [ ] `gofmt` produces no changes.
- [ ] `go vet ./...` passes.
- [ ] `go test -race -count=1 ./...` passes.
- [ ] native and `linux/arm64` builds pass.
- [ ] exact CLI version check passes.
- [ ] Bafflewick acceptance suite passes.

## Evidence

- [ ] every PRD criterion maps to named test/acceptance evidence.
- [ ] `generated/EDD.md` is recovered from the exact source commit.
- [ ] `generated/COMPARISON.md` records matches, deliberate limits and unknowns.

Tag format: `v0.1.0`, `v0.2.0`, and so on.
