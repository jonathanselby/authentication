# Bafflewick acceptance example

Bafflewick is fictional. The executable acceptance suite creates ephemeral RSA and P-256 keys in memory, so the repository never commits live credentials.

```bash
go test ./internal/authn -count=1 -v
```

The suite demonstrates:

- local PBKDF2 verification and current security floors;
- RFC 6238 six-digit TOTP vector and rejection boundaries;
- pinned-key OIDC including nonce, multiple audiences/`azp`, trusted additional audiences and isolate-mode refusal;
- WebAuthn assertion verification with UP/UV, RP/origin/challenge, counter warning and cross-origin refusal;
- exactly two break-glass keyholders;
- generic credential denial and configuration rejection.

`authcheck` consumes deployment-owned verification material from `-config` and one authentication attempt from `-request`. It verifies credentials only; credential enrolment, storage, session management, rate limiting and remote federation discovery stay outside the component.
