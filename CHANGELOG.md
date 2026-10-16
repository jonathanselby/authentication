# Changelog

## 0.1.0 — 2026-10-17

- initial verification-only authentication component;
- Go 1.26 standard-library PBKDF2-HMAC-SHA256 with 600,000-iteration security floor;
- bounded six-digit RFC 6238 TOTP verification;
- pinned RS256 OIDC validation with signature-before-identity-decision, issuer/audience/`azp`/nonce/time checks;
- isolate-mode federation refusal;
- pre-registered WebAuthn P-256 assertion verification with UP/optional UV and counter warning;
- exactly two registered break-glass keyholders;
- generic credential denial separated from configuration/execution failure;
- PRD, EDD, protocol boundary, architecture, CI and code-derived evidence;
- race tests and `linux/arm64` build proof.
