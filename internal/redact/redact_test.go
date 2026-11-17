package redact

import (
	"strings"
	"testing"
)

func TestRedactPatterns(t *testing.T) {
	cases := []struct{ name, in, kind, secret string }{
		{"aws", "key AKIAIOSFODNN7EXAMPLE used", KindAWSKey, "AKIAIOSFODNN7EXAMPLE"},
		{"bearer", "Authorization: Bearer abcdef1234567890xyz", KindBearer, "abcdef1234567890xyz"},
		{"apikey", "api_key=sk_live_abcdef123456", KindAPIKey, "sk_live_abcdef123456"},
		{"apikey-dash", `{"api-key": "abcd1234efgh5678"}`, KindAPIKey, "abcd1234efgh5678"},
		{"privkey", "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef\n-----END RSA PRIVATE KEY-----\ny", KindPrivateKey, "MIIEabc"},
		{"password", "login password=Hunter2!x ok", KindPassword, "Hunter2!x"},
		{"passwd", "passwd: s3cr3t", KindPassword, "s3cr3t"},
		{"secret", "client_secret=abcDEF", KindPassword, "abcDEF"},
		{"token", "access_token=zzz999", KindPassword, "zzz999"},
		{"jwt", "t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4 end", KindJWT, "eyJhbGciOiJIUzI1NiJ9"},
		{"card", "card 4111 1111 1111 1111 paid", KindCreditCard, "4111 1111 1111 1111"},
		{"card-dashes", "4111-1111-1111-1111", KindCreditCard, "4111-1111-1111-1111"},
		{"email", "mail bob.smith@example.com now", KindEmail, "bob.smith@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, fs := Redact(tc.in)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret still present: %q", out)
			}
			if !strings.Contains(out, "[REDACTED:"+tc.kind+"]") {
				t.Fatalf("missing tag for %s: %q", tc.kind, out)
			}
			found := false
			for _, f := range fs {
				if f.Kind == tc.kind && f.Count == 1 {
					found = true
				}
			}
			if !found {
				t.Fatalf("findings %v lack %s x1", fs, tc.kind)
			}
		})
	}
}

func TestRedactNegatives(t *testing.T) {
	benign := []struct{ name, in string }{
		{"aws", "AKIA is a prefix; AKIASHORT is too short"},
		{"bearer", "the bearer token was rejected"},
		{"apikey", "api_key=short"},
		{"privkey", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"},
		{"password", "password policy requires 12 characters"},
		{"jwt", "eyJ only and a.b.c"},
		{"card", "order 4111 1111 1111 1112 and id 1234567890123"},
		{"email", "user at example dot com, foo@bar"},
	}
	for _, tc := range benign {
		t.Run(tc.name, func(t *testing.T) {
			out, fs := Redact(tc.in)
			if out != tc.in || len(fs) != 0 {
				t.Fatalf("benign text changed: %q -> %q (%v)", tc.in, out, fs)
			}
		})
	}
}

func TestRedactCountsAndNoValues(t *testing.T) {
	out, fs := Redact("a@x.io b@y.io password=abc")
	s := Summary(fs)
	if s[KindEmail] != 2 || s[KindPassword] != 1 {
		t.Fatalf("summary %v", s)
	}
	if strings.Contains(out, "a@x.io") || !strings.Contains(out, "password=[REDACTED:password]") {
		t.Fatalf("out %q", out)
	}
}

func TestNoDoubleRedactionOfJWTInTokenPair(t *testing.T) {
	_, fs := Redact("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4")
	if s := Summary(fs); s[KindJWT] != 1 || s[KindPassword] != 0 {
		t.Fatalf("%v", s)
	}
}
