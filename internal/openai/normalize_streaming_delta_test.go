package openai

import "testing"

func TestNormalizeStreamingDelta_RepeatedCharBoundary(t *testing.T) {
	// Streaming splits at repeated-digit boundaries: must not wrongly merge the first character of "43" with the last character of "194".
	cur, d := normalizeStreamingDelta("https://x:194", "43")
	if want := "https://x:19443"; cur != want {
		t.Fatalf("next: want %q got %q", want, cur)
	}
	if d != "43" {
		t.Fatalf("delta: want %q got %q", "43", d)
	}
}

func TestNormalizeStreamingDelta_CumulativePrefix(t *testing.T) {
	cur, d := normalizeStreamingDelta("today", "today weather")
	if cur != "today weather" || d != " weather" {
		t.Fatalf("got cur=%q d=%q", cur, d)
	}
}

func TestNormalizeStreamingDelta_FullRetransmit(t *testing.T) {
	cur, d := normalizeStreamingDelta("today", "today")
	if d != "" || cur != "today" {
		t.Fatalf("got cur=%q d=%q", cur, d)
	}
}

func TestNormalizeStreamingDelta_SingleRuneRepeated(t *testing.T) {
	cur, d := normalizeStreamingDelta("A", "A")
	if want := "AA"; cur != want {
		t.Fatalf("next: want %q got %q", want, cur)
	}
	if d != "A" {
		t.Fatalf("delta: want %q got %q", "A", d)
	}
	cur, d = normalizeStreamingDelta("4", "4")
	if want := "44"; cur != want {
		t.Fatalf("next: want %q got %q", want, cur)
	}
	if d != "4" {
		t.Fatalf("delta: want %q got %q", "4", d)
	}
}

func TestNormalizeStreamingDelta_CumulativeExtendsNumber(t *testing.T) {
	// After buffering "194", receive the cumulative string "19443" (note "1943" is not a prefix of "19443", so HasPrefix cannot be tested with a mistakenly written intermediate state).
	cur, d := normalizeStreamingDelta("194", "19443")
	if want := "19443"; cur != want {
		t.Fatalf("next: want %q got %q", want, cur)
	}
	if d != "43" {
		t.Fatalf("delta: want %q got %q", "43", d)
	}
}
