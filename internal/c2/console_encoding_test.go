package c2

import (
	"encoding/base64"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func mustGBK(t *testing.T, s string) []byte {
	t.Helper()
	out, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNormalizeConsoleOutput_WindowsGBK(t *testing.T) {
	raw := mustGBK(t, "Chinese Testing")
	got := NormalizeConsoleOutput(raw, "windows")
	if got != "Chinese Testing" {
		t.Fatalf("got %q want Chinese Testing", got)
	}
}

func TestNormalizeConsoleOutput_UTF8Passthrough(t *testing.T) {
	raw := []byte("hello world")
	got := NormalizeConsoleOutput(raw, "linux")
	if got != "hello world" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveTaskResultText_PrefersB64(t *testing.T) {
	raw := mustGBK(t, "Purchase Order")
	b64 := base64.StdEncoding.EncodeToString(raw)
	got := ResolveTaskResultText("", b64, "windows")
	if got != "Purchase Order" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveTaskResultText_PlainFallback(t *testing.T) {
	raw := mustGBK(t, "Testing")
	got := ResolveTaskResultText(string(raw), "", "windows")
	if got != "Testing" {
		t.Fatalf("got %q", got)
	}
}
