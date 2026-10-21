package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestLocalAndBreakGlass(t *testing.T) {
	p, err := PBKDF2Record("u", "secret", []byte("1234567890123456"), MinPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(p, "secret") || VerifyPassword(p, "bad") {
		t.Fatal("password verification contract failed")
	}
	a, err := BreakGlassFromPassword("a", "KEYA", []byte("aaaaaaaaaaaaaaaa"), MinPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BreakGlassFromPassword("b", "KEYB", []byte("bbbbbbbbbbbbbbbb"), MinPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := VerifyBreakGlass([]BreakGlassRecord{a, b}, map[string]string{"b": "KEYB", "a": "KEYA"})
	if err != nil || len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("break glass: ids=%v err=%v", ids, err)
	}
}

func TestPasswordFloors(t *testing.T) {
	if _, err := PBKDF2Record("u", "secret", []byte("short"), MinPBKDF2Iterations); err == nil {
		t.Fatal("short salt accepted")
	}
	if _, err := PBKDF2Record("u", "secret", []byte("1234567890123456"), MinPBKDF2Iterations-1); err == nil {
		t.Fatal("weak work factor accepted")
	}
	if _, err := PBKDF2Record("u", "secret", []byte("1234567890123456"), MaxPBKDF2Iterations+1); err == nil {
		t.Fatal("excessive work factor accepted")
	}
}

func TestTOTP(t *testing.T) {
	raw := []byte("12345678901234567890")
	sec := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	now := time.Unix(59, 0)
	ok, err := VerifyTOTP(sec, totp(raw, 1), now, 0)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if got := totp(raw, 1); got != "287082" {
		t.Fatalf("RFC 6238 six-digit vector mismatch: %s", got)
	}
	if ok, _ := VerifyTOTP(sec, "28708x", now, 0); ok {
		t.Fatal("non-numeric TOTP accepted")
	}
	if _, err := VerifyTOTP(sec, "287082", now, MaxTOTPWindow+1); err == nil {
		t.Fatal("excessive TOTP window accepted")
	}
}

func TestTOTPRejectsShortSecret(t *testing.T) {
	sec := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("too-short"))
	if _, err := VerifyTOTP(sec, "000000", time.Now(), 0); err == nil {
		t.Fatal("short TOTP secret accepted")
	}
}

func rsaFixture(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func oidcToken(t *testing.T, priv *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	h := base64.RawURLEncoding.EncodeToString([]byte("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"))
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	p := base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestOIDC(t *testing.T) {
	priv, pub := rsaFixture(t)
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	claims := map[string]any{"iss": "issuer", "aud": "client", "sub": "sam", "exp": now.Add(time.Hour).Unix(), "nonce": "n-123"}
	tok := oidcToken(t, priv, claims)
	sub, err := VerifyOIDC(tok, OIDCConfig{Issuer: "issuer", Audience: "client", PublicKeyPEM: pub}, "n-123", now)
	if err != nil || sub != "sam" {
		t.Fatalf("%s %v", sub, err)
	}
}

func TestOIDCMultipleAudienceRequiresAZPAndTrust(t *testing.T) {
	priv, pub := rsaFixture(t)
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	cfg := OIDCConfig{Issuer: "issuer", Audience: "client", TrustedAudiences: []string{"api"}, PublicKeyPEM: pub}
	good := oidcToken(t, priv, map[string]any{"iss": "issuer", "aud": []string{"client", "api"}, "azp": "client", "sub": "sam", "exp": now.Add(time.Hour).Unix()})
	if _, err := VerifyOIDC(good, cfg, "", now); err != nil {
		t.Fatalf("valid multi-audience token rejected: %v", err)
	}
	missingAZP := oidcToken(t, priv, map[string]any{"iss": "issuer", "aud": []string{"client", "api"}, "sub": "sam", "exp": now.Add(time.Hour).Unix()})
	if _, err := VerifyOIDC(missingAZP, cfg, "", now); err == nil {
		t.Fatal("multi-audience token without azp accepted")
	}
	untrusted := oidcToken(t, priv, map[string]any{"iss": "issuer", "aud": []string{"client", "other"}, "azp": "client", "sub": "sam", "exp": now.Add(time.Hour).Unix()})
	if _, err := VerifyOIDC(untrusted, cfg, "", now); err == nil {
		t.Fatal("untrusted additional audience accepted")
	}
}

func TestOIDCNonceAndTimeBounds(t *testing.T) {
	priv, pub := rsaFixture(t)
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	cfg := OIDCConfig{Issuer: "issuer", Audience: "client", PublicKeyPEM: pub, ClockSkewSeconds: 30}
	tok := oidcToken(t, priv, map[string]any{"iss": "issuer", "aud": "client", "sub": "sam", "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(20 * time.Second).Unix(), "nonce": "good"})
	if _, err := VerifyOIDC(tok, cfg, "good", now); err != nil {
		t.Fatalf("clock skew should permit token: %v", err)
	}
	if _, err := VerifyOIDC(tok, cfg, "wrong", now); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	expired := oidcToken(t, priv, map[string]any{"iss": "issuer", "aud": "client", "sub": "sam", "exp": now.Add(-31 * time.Second).Unix()})
	if _, err := VerifyOIDC(expired, cfg, "", now); err == nil {
		t.Fatal("expired token beyond skew accepted")
	}
}

func TestAuthenticateUsesTrustedOIDCContext(t *testing.T) {
	priv, pub := rsaFixture(t)
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	cfg := Config{OIDC: &OIDCConfig{Issuer: "issuer", Audience: "client", PublicKeyPEM: pub}}
	tok := oidcToken(t, priv, map[string]any{"iss": "issuer", "aud": "client", "sub": "sam", "exp": now.Add(time.Hour).Unix(), "nonce": "trusted"})
	res, err := Authenticate(cfg, Request{Method: "oidc", OIDCToken: tok}, TrustedContext{Now: now, OIDCNonce: "trusted"})
	if err != nil || !res.Authenticated || res.Subject != "sam" {
		t.Fatalf("trusted OIDC context rejected: %+v %v", res, err)
	}
	res, err = Authenticate(cfg, Request{Method: "oidc", OIDCToken: tok}, TrustedContext{Now: now, OIDCNonce: "wrong"})
	if err != nil || res.Authenticated {
		t.Fatalf("wrong trusted nonce accepted: %+v %v", res, err)
	}
}

func TestIsolateRejectsOIDC(t *testing.T) {
	_, pub := rsaFixture(t)
	cfg := Config{OIDC: &OIDCConfig{Issuer: "issuer", Audience: "client", PublicKeyPEM: pub}}
	r, err := Authenticate(cfg, Request{Method: "oidc", OIDCToken: "not-even-a-token"}, TrustedContext{IsolateMode: true})
	if err != nil || r.Authenticated || r.Reason != "federation disabled in isolate mode" {
		t.Fatalf("%+v %v", r, err)
	}
}

func passkeyFixture(t *testing.T, requireUV bool, flags byte, storedCount, newCount uint32, crossOrigin bool) (PasskeyRecord, PasskeyAssertion, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	client := map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://crab.local"}
	if crossOrigin {
		client["crossOrigin"] = true
	}
	cd, _ := json.Marshal(client)
	rp := sha256.Sum256([]byte("crab.local"))
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, flags, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(ad[33:37], newCount)
	ch := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), ch[:]...)
	sum := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return PasskeyRecord{
			UserID:                  "u",
			RPID:                    "crab.local",
			Origin:                  "https://crab.local",
			PublicKeyPEM:            pub,
			RequireUserVerification: requireUV,
			SignCount:               storedCount,
		}, PasskeyAssertion{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(cd),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(ad),
			Signature:         base64.RawURLEncoding.EncodeToString(sig),
		}, challenge
}

func TestPasskey(t *testing.T) {
	r, a, challenge := passkeyFixture(t, true, 0x05, 4, 5, false)
	v, err := VerifyPasskey(r, a, challenge)
	if err != nil || v.SignCount != 5 || v.CounterWarning {
		t.Fatalf("passkey verification: %+v %v", v, err)
	}
	if _, err := VerifyPasskey(r, a, "attacker-chosen"); err == nil {
		t.Fatal("assertion accepted against wrong trusted challenge")
	}
}

func TestPasskeyRequiresUVWhenConfigured(t *testing.T) {
	r, a, challenge := passkeyFixture(t, true, 0x01, 0, 1, false)
	if _, err := VerifyPasskey(r, a, challenge); err == nil {
		t.Fatal("passkey without UV accepted when UV required")
	}
}

func TestPasskeyCounterWarningAndCrossOriginRefusal(t *testing.T) {
	r, a, challenge := passkeyFixture(t, false, 0x01, 5, 5, false)
	v, err := VerifyPasskey(r, a, challenge)
	if err != nil || !v.CounterWarning {
		t.Fatalf("expected counter warning: %+v %v", v, err)
	}
	r, a, challenge = passkeyFixture(t, false, 0x01, 0, 1, true)
	if _, err := VerifyPasskey(r, a, challenge); err == nil {
		t.Fatal("cross-origin assertion accepted")
	}
}

func TestAuthenticatePasskeyRequiresTrustedChallenge(t *testing.T) {
	r, a, challenge := passkeyFixture(t, false, 0x01, 0, 1, false)
	cfg := Config{Passkeys: []PasskeyRecord{r}}
	req := Request{Method: "passkey", UserID: "u", Passkey: &a}
	res, err := Authenticate(cfg, req, TrustedContext{})
	if err != nil || res.Authenticated {
		t.Fatalf("passkey authenticated without trusted challenge: %+v %v", res, err)
	}
	res, err = Authenticate(cfg, req, TrustedContext{PasskeyChallenge: challenge})
	if err != nil || !res.Authenticated {
		t.Fatalf("passkey rejected with trusted challenge: %+v %v", res, err)
	}
}

func TestAuthenticateReturnsGenericDenial(t *testing.T) {
	p, err := PBKDF2Record("u", "secret", []byte("1234567890123456"), MinPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Local: []PasswordRecord{p}}
	res, err := Authenticate(cfg, Request{Method: "local", UserID: "u", Password: "wrong"}, TrustedContext{})
	if err != nil || res.Authenticated || res.Reason != "credentials rejected" {
		t.Fatalf("unexpected denial: %+v %v", res, err)
	}
	res, err = Authenticate(cfg, Request{Method: "local", UserID: "not-a-user", Password: "wrong"}, TrustedContext{})
	if err != nil || res.Authenticated || res.Reason != "credentials rejected" {
		t.Fatalf("unknown user denial leaked detail: %+v %v", res, err)
	}
	res, err = Authenticate(cfg, Request{Method: "nope"}, TrustedContext{})
	if err != nil || res.Authenticated || !strings.Contains(res.Reason, "unsupported") {
		t.Fatalf("unsupported method not a deterministic denial: %+v %v", res, err)
	}
}

func TestValidateConfig(t *testing.T) {
	p, err := PBKDF2Record("u", "secret", []byte("1234567890123456"), MinPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(Config{Local: []PasswordRecord{p, p}}); err == nil {
		t.Fatal("duplicate local user accepted")
	}
	bad := p
	bad.Iterations = MinPBKDF2Iterations - 1
	if err := ValidateConfig(Config{Local: []PasswordRecord{bad}}); err == nil {
		t.Fatal("weak password record accepted")
	}
	bad = p
	bad.Iterations = MaxPBKDF2Iterations + 1
	if err := ValidateConfig(Config{Local: []PasswordRecord{bad}}); err == nil {
		t.Fatal("excessive password work factor accepted")
	}

	a, err := BreakGlassFromPassword("a", "KEYA", []byte("aaaaaaaaaaaaaaaa"), MinPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(Config{BreakGlass: []BreakGlassRecord{a, a}}); err == nil {
		t.Fatal("duplicate break-glass keyholder accepted")
	}
}
