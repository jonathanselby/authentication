package authn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	MinPBKDF2Iterations     = 600000
	MinSaltBytes            = 16
	PasswordHashBytes       = 32
	MinTOTPSecretBytes      = 20
	MaxTOTPWindow           = 2
	MaxOIDCClockSkewSeconds = 300
)

type PasswordRecord struct {
	UserID     string `json:"user_id"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Hash       string `json:"hash"`
}

type TOTPRecord struct {
	UserID string `json:"user_id"`
	Secret string `json:"secret"`
	Window int    `json:"window"`
}

type OIDCConfig struct {
	Issuer           string   `json:"issuer"`
	Audience         string   `json:"audience"`
	TrustedAudiences []string `json:"trusted_audiences,omitempty"`
	PublicKeyPEM     string   `json:"public_key_pem"`
	ClockSkewSeconds int      `json:"clock_skew_seconds,omitempty"`
}

type PasskeyRecord struct {
	UserID                  string `json:"user_id"`
	RPID                    string `json:"rp_id"`
	Origin                  string `json:"origin"`
	PublicKeyPEM            string `json:"public_key_pem"`
	RequireUserVerification bool   `json:"require_user_verification,omitempty"`
	SignCount               uint32 `json:"sign_count,omitempty"`
}

type BreakGlassRecord struct {
	UserID     string `json:"user_id"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Hash       string `json:"hash"`
}

type Config struct {
	Local      []PasswordRecord   `json:"local,omitempty"`
	TOTP       []TOTPRecord       `json:"totp,omitempty"`
	OIDC       *OIDCConfig        `json:"oidc,omitempty"`
	Passkeys   []PasskeyRecord    `json:"passkeys,omitempty"`
	BreakGlass []BreakGlassRecord `json:"break_glass,omitempty"`
}

type PasskeyAssertion struct {
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	Challenge         string `json:"challenge"`
}

type Request struct {
	Method         string            `json:"method"`
	UserID         string            `json:"user_id,omitempty"`
	Password       string            `json:"password,omitempty"`
	TOTP           string            `json:"totp,omitempty"`
	OIDCToken      string            `json:"oidc_token,omitempty"`
	OIDCNonce      string            `json:"oidc_nonce,omitempty"`
	Passkey        *PasskeyAssertion `json:"passkey,omitempty"`
	BreakGlassKeys map[string]string `json:"break_glass_keys,omitempty"`
	IsolateMode    bool              `json:"isolate_mode,omitempty"`
	Now            time.Time         `json:"now,omitempty"`
}

type Result struct {
	Authenticated  bool     `json:"authenticated"`
	Subject        string   `json:"subject,omitempty"`
	Method         string   `json:"method"`
	Keyholders     []string `json:"keyholders,omitempty"`
	SignCount      uint32   `json:"sign_count,omitempty"`
	CounterWarning bool     `json:"counter_warning,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

type PasskeyVerification struct {
	SignCount      uint32
	CounterWarning bool
}

func ValidateConfig(c Config) error {
	seen := map[string]string{}
	for _, p := range c.Local {
		if p.UserID == "" || duplicate(seen, p.UserID, "local") {
			return errors.New("invalid or duplicate local user")
		}
		if err := validatePasswordRecord(p); err != nil {
			return err
		}
	}
	for _, t := range c.TOTP {
		if t.UserID == "" || duplicate(seen, t.UserID, "totp") {
			return errors.New("invalid or duplicate TOTP user")
		}
		if t.Window < 0 || t.Window > MaxTOTPWindow {
			return errors.New("TOTP window out of range")
		}
		if _, err := decodeTOTPSecret(t.Secret); err != nil {
			return err
		}
	}
	for _, p := range c.Passkeys {
		if p.UserID == "" || duplicate(seen, p.UserID, "passkey") {
			return errors.New("invalid or duplicate passkey user")
		}
		if p.RPID == "" || p.Origin == "" {
			return errors.New("passkey rp_id and origin are required")
		}
		if _, err := parseECDSA(p.PublicKeyPEM); err != nil {
			return err
		}
	}
	for _, b := range c.BreakGlass {
		if b.UserID == "" {
			return errors.New("break-glass user_id required")
		}
		p := PasswordRecord{UserID: b.UserID, Salt: b.Salt, Iterations: b.Iterations, Hash: b.Hash}
		if err := validatePasswordRecord(p); err != nil {
			return err
		}
	}
	if c.OIDC != nil {
		if err := validateOIDCConfig(*c.OIDC); err != nil {
			return err
		}
	}
	return nil
}

func duplicate(seen map[string]string, id, method string) bool {
	k := method + "\x00" + id
	if seen[k] != "" {
		return true
	}
	seen[k] = method
	return false
}

func Authenticate(c Config, r Request) (Result, error) {
	if err := ValidateConfig(c); err != nil {
		return Result{}, err
	}
	now := r.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	deny := func(reason string) (Result, error) {
		return Result{Authenticated: false, Method: r.Method, Reason: reason}, nil
	}
	switch r.Method {
	case "local":
		p, ok := findPassword(c.Local, r.UserID)
		if !ok || !VerifyPassword(p, r.Password) {
			return deny("credentials rejected")
		}
		return Result{Authenticated: true, Subject: r.UserID, Method: r.Method}, nil
	case "totp":
		t, ok := findTOTP(c.TOTP, r.UserID)
		if !ok {
			return deny("credentials rejected")
		}
		ok, err := VerifyTOTP(t.Secret, r.TOTP, now, t.Window)
		if err != nil || !ok {
			return deny("credentials rejected")
		}
		return Result{Authenticated: true, Subject: r.UserID, Method: r.Method}, nil
	case "oidc":
		if r.IsolateMode {
			return deny("federation disabled in isolate mode")
		}
		if c.OIDC == nil {
			return deny("OIDC not configured")
		}
		sub, err := VerifyOIDC(r.OIDCToken, *c.OIDC, r.OIDCNonce, now)
		if err != nil {
			return deny("credentials rejected")
		}
		return Result{Authenticated: true, Subject: sub, Method: r.Method}, nil
	case "passkey":
		p, ok := findPasskey(c.Passkeys, r.UserID)
		if !ok || r.Passkey == nil {
			return deny("credentials rejected")
		}
		v, err := VerifyPasskey(p, *r.Passkey)
		if err != nil {
			return deny("credentials rejected")
		}
		res := Result{Authenticated: true, Subject: r.UserID, Method: r.Method, SignCount: v.SignCount, CounterWarning: v.CounterWarning}
		if v.CounterWarning {
			res.Reason = "passkey signature counter did not increase"
		}
		return res, nil
	case "breakglass":
		ids, err := VerifyBreakGlass(c.BreakGlass, r.BreakGlassKeys)
		if err != nil {
			return deny("credentials rejected")
		}
		return Result{Authenticated: true, Subject: "breakglass", Method: r.Method, Keyholders: ids}, nil
	default:
		return deny("unsupported authentication method")
	}
}

func PBKDF2Record(user, password string, salt []byte, iterations int) (PasswordRecord, error) {
	if user == "" || len(salt) < MinSaltBytes || iterations < MinPBKDF2Iterations {
		return PasswordRecord{}, errors.New("password record parameters below minimum")
	}
	h, err := pbkdf2.Key(sha256.New, password, salt, iterations, PasswordHashBytes)
	if err != nil {
		return PasswordRecord{}, err
	}
	return PasswordRecord{
		UserID:     user,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Iterations: iterations,
		Hash:       base64.StdEncoding.EncodeToString(h),
	}, nil
}

func validatePasswordRecord(r PasswordRecord) error {
	if r.UserID == "" || r.Iterations < MinPBKDF2Iterations {
		return errors.New("password record below minimum work factor")
	}
	salt, err := base64.StdEncoding.DecodeString(r.Salt)
	if err != nil || len(salt) < MinSaltBytes {
		return errors.New("password record has invalid salt")
	}
	h, err := base64.StdEncoding.DecodeString(r.Hash)
	if err != nil || len(h) != PasswordHashBytes {
		return errors.New("password record has invalid hash")
	}
	return nil
}

func VerifyPassword(r PasswordRecord, password string) bool {
	if err := validatePasswordRecord(r); err != nil {
		return false
	}
	salt, _ := base64.StdEncoding.DecodeString(r.Salt)
	want, _ := base64.StdEncoding.DecodeString(r.Hash)
	got, err := pbkdf2.Key(sha256.New, password, salt, r.Iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}

func VerifyTOTP(secret, code string, now time.Time, window int) (bool, error) {
	if window < 0 || window > MaxTOTPWindow || now.Unix() < 0 {
		return false, errors.New("invalid TOTP parameters")
	}
	if len(code) != 6 {
		return false, nil
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return false, nil
		}
	}
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return false, err
	}
	counter := now.Unix() / 30
	for d := -window; d <= window; d++ {
		if counter+int64(d) < 0 {
			continue
		}
		want := totp(raw, uint64(counter+int64(d)))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true, nil
		}
	}
	return false, nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(raw) < MinTOTPSecretBytes {
		return nil, errors.New("invalid or short TOTP secret")
	}
	return raw, nil
}

func totp(secret []byte, counter uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(b[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 0x0f
	n := (uint32(h[o])&0x7f)<<24 | uint32(h[o+1])<<16 | uint32(h[o+2])<<8 | uint32(h[o+3])
	n %= 1000000
	return left6(n)
}

func left6(n uint32) string {
	b := []byte("000000")
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b)
}

func VerifyOIDC(tok string, c OIDCConfig, expectedNonce string, now time.Time) (string, error) {
	if err := validateOIDCConfig(c); err != nil {
		return "", err
	}
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return "", errors.New("invalid token")
	}
	var head struct {
		Alg string `json:"alg"`
	}
	if err := decodeJSON(p[0], &head); err != nil || head.Alg != "RS256" {
		return "", errors.New("unexpected JWT algorithm")
	}
	var claims struct {
		Iss   string          `json:"iss"`
		Aud   json.RawMessage `json:"aud"`
		Sub   string          `json:"sub"`
		Exp   int64           `json:"exp"`
		Nbf   int64           `json:"nbf,omitempty"`
		Nonce string          `json:"nonce,omitempty"`
		Azp   string          `json:"azp,omitempty"`
	}
	if err := decodeJSON(p[1], &claims); err != nil {
		return "", err
	}

	// Authenticate the token before trusting any claim value for an identity decision.
	pub, err := parseRSA(c.PublicKeyPEM)
	if err != nil {
		return "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return "", errors.New("OIDC signature rejected")
	}

	if claims.Iss != c.Issuer || claims.Sub == "" || claims.Exp == 0 {
		return "", errors.New("OIDC claims rejected")
	}
	audiences, err := parseAudiences(claims.Aud)
	if err != nil || !contains(audiences, c.Audience) {
		return "", errors.New("OIDC audience rejected")
	}
	trusted := map[string]bool{c.Audience: true}
	for _, a := range c.TrustedAudiences {
		trusted[a] = true
	}
	for _, a := range audiences {
		if !trusted[a] {
			return "", errors.New("OIDC contains untrusted audience")
		}
	}
	if len(audiences) > 1 && claims.Azp == "" {
		return "", errors.New("OIDC azp required for multiple audiences")
	}
	if claims.Azp != "" && claims.Azp != c.Audience {
		return "", errors.New("OIDC azp rejected")
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return "", errors.New("OIDC nonce rejected")
	}
	skew := int64(c.ClockSkewSeconds)
	if now.Unix() > claims.Exp+skew {
		return "", errors.New("OIDC token expired")
	}
	if claims.Nbf != 0 && now.Unix()+skew < claims.Nbf {
		return "", errors.New("OIDC token not yet valid")
	}
	return claims.Sub, nil
}
func validateOIDCConfig(c OIDCConfig) error {
	if c.Issuer == "" || c.Audience == "" || c.PublicKeyPEM == "" {
		return errors.New("OIDC issuer, audience and pinned public key are required")
	}
	if c.ClockSkewSeconds < 0 || c.ClockSkewSeconds > MaxOIDCClockSkewSeconds {
		return errors.New("OIDC clock skew out of range")
	}
	seen := map[string]bool{c.Audience: true}
	for _, a := range c.TrustedAudiences {
		if a == "" || seen[a] {
			return errors.New("invalid or duplicate trusted OIDC audience")
		}
		seen[a] = true
	}
	_, err := parseRSA(c.PublicKeyPEM)
	return err
}

func parseAudiences(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("audience missing")
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil, errors.New("audience empty")
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 {
		return nil, errors.New("invalid audience")
	}
	seen := map[string]bool{}
	for _, a := range many {
		if a == "" || seen[a] {
			return nil, errors.New("invalid or duplicate audience")
		}
		seen[a] = true
	}
	return many, nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func decodeJSON(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func parseRSA(s string) (*rsa.PublicKey, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("invalid RSA PEM")
	}
	if k, err := x509.ParsePKIXPublicKey(b.Bytes); err == nil {
		if r, ok := k.(*rsa.PublicKey); ok && r.N.BitLen() >= 2048 {
			return r, nil
		}
	}
	if r, err := x509.ParsePKCS1PublicKey(b.Bytes); err == nil && r.N.BitLen() >= 2048 {
		return r, nil
	}
	return nil, errors.New("invalid or short RSA public key")
}

func VerifyPasskey(r PasskeyRecord, a PasskeyAssertion) (PasskeyVerification, error) {
	if r.RPID == "" || r.Origin == "" || a.Challenge == "" {
		return PasskeyVerification{}, errors.New("passkey verification parameters missing")
	}
	cd, err := base64.RawURLEncoding.DecodeString(a.ClientDataJSON)
	if err != nil {
		return PasskeyVerification{}, err
	}
	var c struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin,omitempty"`
	}
	if err := json.Unmarshal(cd, &c); err != nil || c.Type != "webauthn.get" || c.Challenge != a.Challenge || c.Origin != r.Origin || c.CrossOrigin {
		return PasskeyVerification{}, errors.New("client data rejected")
	}
	ad, err := base64.RawURLEncoding.DecodeString(a.AuthenticatorData)
	if err != nil || len(ad) < 37 {
		return PasskeyVerification{}, errors.New("invalid authenticator data")
	}
	rp := sha256.Sum256([]byte(r.RPID))
	if !bytes.Equal(ad[:32], rp[:]) || ad[32]&0x01 == 0 {
		return PasskeyVerification{}, errors.New("relying party or user-presence check failed")
	}
	if r.RequireUserVerification && ad[32]&0x04 == 0 {
		return PasskeyVerification{}, errors.New("user verification required")
	}
	pub, err := parseECDSA(r.PublicKeyPEM)
	if err != nil {
		return PasskeyVerification{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil {
		return PasskeyVerification{}, err
	}
	ch := sha256.Sum256(cd)
	msg := make([]byte, 0, len(ad)+len(ch))
	msg = append(msg, ad...)
	msg = append(msg, ch[:]...)
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return PasskeyVerification{}, errors.New("passkey signature rejected")
	}
	count := binary.BigEndian.Uint32(ad[33:37])
	warning := (r.SignCount != 0 || count != 0) && count <= r.SignCount
	return PasskeyVerification{SignCount: count, CounterWarning: warning}, nil
}

func parseECDSA(s string) (*ecdsa.PublicKey, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("invalid ECDSA PEM")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	p, ok := k.(*ecdsa.PublicKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil, errors.New("passkey key must be ECDSA P-256")
	}
	return p, nil
}

func VerifyBreakGlass(records []BreakGlassRecord, keys map[string]string) ([]string, error) {
	if len(keys) != 2 {
		return nil, errors.New("exactly two break-glass keyholders required")
	}
	byID := map[string]BreakGlassRecord{}
	for _, r := range records {
		if r.UserID == "" || byID[r.UserID].UserID != "" {
			return nil, errors.New("invalid or duplicate break-glass keyholder")
		}
		byID[r.UserID] = r
	}
	ids := make([]string, 0, 2)
	for id, key := range keys {
		rec, ok := byID[id]
		if !ok {
			return nil, errors.New("unknown keyholder")
		}
		p := PasswordRecord{UserID: id, Salt: rec.Salt, Iterations: rec.Iterations, Hash: rec.Hash}
		if !VerifyPassword(p, key) {
			return nil, errors.New("invalid break-glass key")
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func BreakGlassFromPassword(user, key string, salt []byte, iterations int) (BreakGlassRecord, error) {
	p, err := PBKDF2Record(user, key, salt, iterations)
	if err != nil {
		return BreakGlassRecord{}, err
	}
	return BreakGlassRecord{UserID: p.UserID, Salt: p.Salt, Iterations: p.Iterations, Hash: p.Hash}, nil
}

func findPassword(xs []PasswordRecord, id string) (PasswordRecord, bool) {
	for _, x := range xs {
		if x.UserID == id {
			return x, true
		}
	}
	return PasswordRecord{}, false
}

func findTOTP(xs []TOTPRecord, id string) (TOTPRecord, bool) {
	for _, x := range xs {
		if x.UserID == id {
			return x, true
		}
	}
	return TOTPRecord{}, false
}

func findPasskey(xs []PasskeyRecord, id string) (PasskeyRecord, bool) {
	for _, x := range xs {
		if x.UserID == id {
			return x, true
		}
	}
	return PasskeyRecord{}, false
}
