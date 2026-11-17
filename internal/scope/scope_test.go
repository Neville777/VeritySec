package scope

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

var now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, js string) *Scope {
	t.Helper()
	s, err := Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse %s: %v", js, err)
	}
	return s
}

func TestParseStrict(t *testing.T) {
	bad := []string{
		``, `null`, `[]`, `"x"`, `{`, `{"included":"a.com"}`, `{"included":[1]}`, `{"included":[""]}`,
		`{"included":["bad host!"]}`, `{"included":["10.0.0.0/33"]}`, `{"unknown":[]}`,
		`{"included":["a.com"]} {}`, `{"expires_at":"tomorrow"}`, `{"included":[{"type":"zzz","value":"a"}]}`,
		`{"included":[{"type":"host","value":"a.com","extra":1}]}`, `{"included":["*.bad_/x"]}`,
		`{"included":["a.*.com"]}`, `{"included":["http://"]}`,
	}
	for _, js := range bad {
		if _, err := Parse([]byte(js)); err == nil {
			t.Errorf("expected error for %q", js)
		}
	}
}

func TestEmptyIncludedMeansNothingInScope(t *testing.T) {
	for _, js := range []string{`{}`, `{"included":[]}`, `{"excluded":["a.com"]}`} {
		s := mustParse(t, js)
		if s.IncludedCount() != 0 {
			t.Fatal("included should be empty")
		}
		if d := Evaluate(s, "example.com", now); d.Result != OutOfScope {
			t.Fatalf("%s: got %v", js, d)
		}
	}
}

func TestMatching(t *testing.T) {
	s := mustParse(t, `{"included":["host.example.org","*.example.com","10.0.0.0/24","192.0.2.7","https://app.other.test:8443/api",
	  {"type":"domain","value":"typed.test"},"2001:db8::/32"],
	  "excluded":["admin.example.com","10.0.0.128/25","http://bad.example.com/x"]}`)
	cases := []struct {
		target string
		want   Result
	}{
		{"host.example.org", InScope},
		{"sub.host.example.org", OutOfScope}, // exact host rule only
		{"example.com", InScope},
		{"a.b.example.com", InScope},
		{"notexample.com", OutOfScope},
		{"admin.example.com", OutOfScope}, // excluded beats included parent
		{"x.admin.example.com", InScope},  // exclusion is exact for bare hosts
		{"10.0.0.5", InScope},
		{"10.0.1.5", OutOfScope},
		{"10.0.0.200", OutOfScope}, // excluded sub-range
		{"10.0.0.0/25", InScope},
		{"10.0.0.0/24", OutOfScope}, // overlaps excluded range
		{"10.0.0.0/16", OutOfScope}, // wider than included
		{"192.0.2.7", InScope},
		{"::ffff:192.0.2.7", InScope},
		{"2001:db8::1", InScope},
		{"[2001:db8::1]:443", InScope},
		{"https://example.com:8080/a/b?q=1", InScope},
		{"example.com:22", InScope},
		{"HTTP://EXAMPLE.COM./x", InScope},
		{"Example.COM.", InScope},
		{"10.0.0.5:80", InScope},
		{"https://app.other.test:8443/api/v1", InScope},
		{"https://app.other.test:8443/api", InScope},
		{"https://app.other.test:8443/apix", OutOfScope},
		{"https://app.other.test:8443/api/../admin", OutOfScope},
		{"https://app.other.test/api", OutOfScope}, // wrong port
		{"app.other.test", OutOfScope},             // no scheme: cannot match a URL prefix
		{"x.typed.test", InScope},
		{"evil.com", OutOfScope},
		{"8.8.8.8", OutOfScope},
		{"", Unknown},
		{"not a host", Unknown},
		{"http://", Unknown},
		{"file:///etc/passwd", Unknown},
		{"2130706433", Unknown},
		{"0x7f.1", Unknown},
		{"127.1", Unknown},
		{"bad_host!.com", Unknown},
		{"münchen.de", Unknown},
	}
	for _, c := range cases {
		if d := Evaluate(s, c.target, now); d.Result != c.want {
			t.Errorf("%q: got %s (%s), want %s", c.target, d.Result, d.Reason, c.want)
		}
	}
}

func TestNameAndIPAreSeparate(t *testing.T) {
	s := mustParse(t, `{"included":["10.0.0.0/8"]}`)
	if d := Evaluate(s, "internal.example.com", now); d.Result != OutOfScope {
		t.Fatalf("a name must not match a CIDR rule: %v", d)
	}
	s = mustParse(t, `{"included":["example.com"]}`)
	if d := Evaluate(s, "93.184.216.34", now); d.Result != OutOfScope {
		t.Fatalf("an IP must not match a name rule: %v", d)
	}
}

func TestExcludedURLPrefix(t *testing.T) {
	s := mustParse(t, `{"included":["bad.example.com"],"excluded":["http://bad.example.com/x"]}`)
	if d := Evaluate(s, "http://bad.example.com/x/y", now); d.Result != OutOfScope {
		t.Fatal(d)
	}
	if d := Evaluate(s, "http://bad.example.com/ok", now); d.Result != InScope {
		t.Fatal(d)
	}
}

func TestExpiry(t *testing.T) {
	s := mustParse(t, `{"included":["example.com"],"expires_at":"2026-01-01T12:00:00Z"}`)
	d := Evaluate(s, "example.com", now)
	if d.Result != OutOfScope || d.Reason != "authorization expired" {
		t.Fatalf("got %+v", d)
	}
	if d := Evaluate(s, "example.com", now.Add(-time.Second)); d.Result != InScope {
		t.Fatalf("got %+v", d)
	}
}

func TestNilScopeIsUnknown(t *testing.T) {
	if d := Evaluate(nil, "example.com", now); d.Result != Unknown {
		t.Fatal(d)
	}
}

func TestExtractTargets(t *testing.T) {
	args := map[string]interface{}{
		"target": "10.0.0.1", "Hosts": "ignored.txt",
		"urls":    []interface{}{"https://a.example/x", "b.example"},
		"options": map[string]interface{}{"base_url": "c.example", "ref": "https://d.example/"},
		"file":    "report.txt", "note": "scan the thing", "t": "12:30", "port": "80", "q": "e.example:8080",
		"cmd": "nmap 10.0.0.9",
	}
	got := ExtractTargets("nmap", args)
	want := []string{"10.0.0.1", "10.0.0.9", "b.example", "c.example", "e.example:8080", "https://a.example/x", "https://d.example/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := ExtractTargets("web_search", map[string]interface{}{"query": "example.com", "url": "https://x.example"}); got != nil {
		t.Fatalf("web_search must yield no targets: %v", got)
	}
	if got := ExtractTargets("web_fetch", map[string]interface{}{"url": "https://x.example/p"}); len(got) != 1 {
		t.Fatalf("web_fetch url: %v", got)
	}
	if got := ExtractTargets("x", map[string]interface{}{"count": 3}); len(got) != 0 {
		t.Fatalf("no target expected: %v", got)
	}
}

func TestExtractFreeText(t *testing.T) {
	got := ExtractTargets("exec", map[string]interface{}{"command": "nmap -sV 10.9.9.9 && curl http://evil.example"})
	want := []string{"10.9.9.9", "evil.example", "http://evil.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for in, must := range map[string]string{
		`curl --url=http://a.example/x?y=1;ls`: "http://a.example/x?y=1",
		`ssh root@b.example -p 22`:             "b.example",
		`ping "c.example"|cat`:                 "c.example",
		`nc 10.1.1.1:4444`:                     "10.1.1.1:4444",
		`scan 10.2.0.0/16,d.example:8080`:      "10.2.0.0/16",
		`curl 2130706433`:                      "2130706433",
		`curl http://[::1]:80/`:                "::1",
		`HOST=e.example run`:                   "e.example",
		`wget ftp://u:p@f.example/file`:        "f.example",
		`curl g.example/path/x`:                "g.example",
	} {
		found := false
		for _, g := range ExtractTargets("exec", map[string]interface{}{"c": in}) {
			if g == must {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: %q not extracted: %v", in, must, ExtractTargets("exec", map[string]interface{}{"c": in}))
		}
	}
	if got := ExtractTargets("exec", map[string]interface{}{"c": "cat report.txt and main.go in /etc/passwd 12:30"}); len(got) != 0 {
		t.Fatalf("unexpected: %v", got)
	}
	if got := ExtractTargets("web_search", map[string]interface{}{"query": "nmap 10.9.9.9 evil.example"}); got != nil {
		t.Fatalf("web_search exempt: %v", got)
	}
}

func TestEvaluateResolved(t *testing.T) {
	s, err := Parse([]byte(`{"included":["*.example.com","10.0.0.0/24"],"excluded":["10.0.0.128/25","203.0.113.0/24"]}`))
	if err != nil {
		t.Fatal(err)
	}
	ip := func(x string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(x)} }
	cases := []struct {
		ips  []netip.Addr
		want Result
	}{
		{nil, InScope},
		{ip("93.184.216.34"), InScope},
		{ip("203.0.113.9"), OutOfScope},
		{ip("10.0.0.200"), OutOfScope},
		{ip("10.0.0.5"), InScope},
		{ip("127.0.0.1"), OutOfScope},
		{ip("169.254.169.254"), OutOfScope},
		{ip("192.168.1.1"), OutOfScope},
		{ip("::ffff:127.0.0.1"), OutOfScope},
	}
	for _, c := range cases {
		d := EvaluateResolved(s, "www.example.com", now, c.ips)
		if d.Result != c.want {
			t.Errorf("%v: %v (%s)", c.ips, d.Result, d.Reason)
		}
		if d.Result == OutOfScope && !IsResolvedRefusal(d.Reason) {
			t.Errorf("reason %q", d.Reason)
		}
	}
	s2, _ := Parse([]byte(`{"included":["localhost","127.0.0.0/8"]}`))
	if d := EvaluateResolved(s2, "localhost", now, ip("127.0.0.1")); d.Result != InScope {
		t.Fatalf("explicit loopback include: %v", d)
	}
	// IP literals and out-of-scope names are not altered
	if d := EvaluateResolved(s, "10.0.0.5", now, ip("127.0.0.1")); d.Result != InScope {
		t.Fatal(d)
	}
	if d := EvaluateResolved(s, "evil.org", now, ip("10.0.0.5")); d.Result != OutOfScope || IsResolvedRefusal(d.Reason) {
		t.Fatal(d)
	}
}
