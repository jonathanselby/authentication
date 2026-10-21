package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jonathanselby/authentication/internal/authn"
)

const version = "0.1.0"

func main() {
	var cfg, req, oidcNonce, passkeyChallenge string
	var isolate, v bool
	flag.StringVar(&cfg, "config", "", "authentication config JSON")
	flag.StringVar(&req, "request", "", "authentication request JSON")
	flag.StringVar(&oidcNonce, "oidc-nonce", "", "expected OIDC nonce from trusted ceremony state")
	flag.StringVar(&passkeyChallenge, "passkey-challenge", "", "expected passkey challenge from trusted ceremony state")
	flag.BoolVar(&isolate, "isolate", false, "disable OIDC federation")
	flag.BoolVar(&v, "version", false, "print version")
	flag.Parse()
	if v {
		fmt.Println("authcheck " + version)
		return
	}
	if cfg == "" || req == "" {
		flag.Usage()
		os.Exit(2)
	}
	var c authn.Config
	var r authn.Request
	if e := read(cfg, &c); e != nil {
		bad(e)
	}
	if e := read(req, &r); e != nil {
		bad(e)
	}
	if e := authn.ValidateConfig(c); e != nil {
		bad(e)
	}
	out, e := authn.Authenticate(c, r, authn.TrustedContext{
		OIDCNonce:        oidcNonce,
		PasskeyChallenge: passkeyChallenge,
		IsolateMode:      isolate,
	})
	if e != nil {
		bad(e)
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if !out.Authenticated {
		os.Exit(1)
	}
}

func read(p string, v any) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}

func bad(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(3) }
