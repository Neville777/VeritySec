package inputs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectMagic(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Kind
	}{
		{"png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 20)...), KindImagePNG},
		{"jpeg", append([]byte{0xff, 0xd8, 0xff, 0xe0}, make([]byte, 20)...), KindImageJPEG},
		{"gif", []byte("GIF89a\x01\x00\x01\x00"), KindImageGIF},
		{"webp", append([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), make([]byte, 8)...), KindImageWebP},
		{"pdf", []byte("%PDF-1.7\n%..."), KindPDF},
		{"zip", append([]byte("PK\x03\x04"), make([]byte, 30)...), KindZip},
		{"gzip", append([]byte{0x1f, 0x8b, 8, 0}, make([]byte, 20)...), KindGzip},
		{"pcap-be", append([]byte{0xa1, 0xb2, 0xc3, 0xd4}, make([]byte, 20)...), KindPcap},
		{"pcap-le", append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 20)...), KindPcap},
		{"pcapng", append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, make([]byte, 20)...), KindPcapng},
		{"text", []byte("hello world, see example.com\n"), KindTextUTF8},
		{"log", []byte("2024-01-02 10:00:00 INFO start\n2024-01-02 10:00:01 WARN x\n2024-01-02 10:00:02 ERROR y\n"), KindTextLogLike},
		{"bin", []byte{0, 1, 2, 3, 0xff, 0xfe}, KindBinaryUnknown},
	}
	for _, c := range cases {
		if got := Detect(c.data, "").Kind; got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestDetectSourceCodeLowConfidence(t *testing.T) {
	d := Detect([]byte("package main\nfunc main() {}\n"), "x.go")
	if d.Kind != KindSourceCode || d.Confidence > 0.6 {
		t.Fatalf("%+v", d)
	}
	if Detect([]byte("package main\n"), "x.txt").Kind == KindSourceCode {
		t.Fatal("extension required")
	}
}

func TestFakePNGMismatch(t *testing.T) {
	d := Detect([]byte("this is just text"), "evil.png")
	if d.Kind != KindTextUTF8 {
		t.Fatalf("kind %s", d.Kind)
	}
	found := false
	for _, r := range d.Reasons {
		if strings.HasPrefix(r, "mismatch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no mismatch reason: %v", d.Reasons)
	}
	ok := Detect([]byte("\x89PNG\r\n\x1a\n0000"), "a.png")
	for _, r := range ok.Reasons {
		if strings.HasPrefix(r, "mismatch") {
			t.Fatal("false mismatch")
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd": "passwd",
		`C:\x\y\z.txt`:     "z.txt",
		"a\x00b\x01c.txt":  "abc.txt",
		"..":               "unnamed",
		"":                 "unnamed",
		"dir/":             "unnamed",
	}
	for in, want := range cases {
		if got := SanitizeFilename(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	long := SanitizeFilename(strings.Repeat("é", 400))
	if len(long) > 255 || len(long)%2 != 0 {
		t.Errorf("long len %d", len(long))
	}
}

func TestExtractIndicators(t *testing.T) {
	text := "see https://App.example.com/login?a=1. and host db.internal.example.org, " +
		"ip 10.0.0.5 range 192.168.1.0/24 again 10.0.0.5 and https://App.example.com/login?a=1 file notes.txt ver 1.2.3.4.5"
	got := ExtractIndicators(text, 100)
	count := map[string]int{}
	vals := map[string]bool{}
	for _, i := range got {
		count[i.Kind+i.Value]++
		vals[i.Kind+":"+i.Value] = true
		if i.Authorized || i.Status != StatusDiscovered {
			t.Fatalf("bad flags %+v", i)
		}
		if !strings.HasPrefix(text[i.Offset:], strings.TrimRight(i.Value, "")) && i.Kind != IndicatorHostname {
			t.Errorf("offset wrong %+v", i)
		}
	}
	for _, c := range count {
		if c != 1 {
			t.Fatalf("duplicates: %v", count)
		}
	}
	for _, w := range []string{
		"url:https://App.example.com/login?a=1", "hostname:app.example.com",
		"hostname:db.internal.example.org", "ipv4:10.0.0.5", "cidr:192.168.1.0/24",
	} {
		if !vals[w] {
			t.Errorf("missing %s in %v", w, vals)
		}
	}
	if vals["hostname:notes.txt"] || vals["ipv4:1.2.3.4"] {
		t.Errorf("false positive: %v", vals)
	}
}

func TestExtractCapAndControl(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString("10.0.0." + string(rune('0'+i%10)) + " h" + strings.Repeat("a", i) + ".example.com\n")
	}
	if n := len(ExtractIndicators(sb.String(), 5)); n != 5 {
		t.Fatalf("cap: %d", n)
	}
	got := ExtractIndicators("ex\x00ample.com 1.1.1.1", 10)
	for _, i := range got {
		if i.Value == "example.com" {
			t.Fatal("control char should split token")
		}
	}
	big := strings.Repeat("x ", MaxIndicatorInput) + "late.example.com"
	if len(ExtractIndicators(big, 10)) != 0 {
		t.Fatal("input beyond 2MB must be ignored")
	}
}

func TestStore(t *testing.T) {
	root := t.TempDir()
	rec, err := Store(root, "eng1", []byte("\x89PNG\r\n\x1a\n0000"), "../x.png")
	if err != nil {
		t.Fatal(err)
	}
	if rec.DetectedKind != KindImagePNG || rec.OriginalName != "x.png" || rec.Size != 12 || len(rec.SHA256) != 64 {
		t.Fatalf("%+v", rec)
	}
	st, err := os.Stat(rec.StoragePath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
	if rec.StoragePath != filepath.Join(root, "inputs", "eng1", rec.ID+".bin") {
		t.Fatal(rec.StoragePath)
	}
	b, _ := os.ReadFile(rec.StoragePath)
	if !bytes.Equal(b, []byte("\x89PNG\r\n\x1a\n0000")) {
		t.Fatal("content differs")
	}
	for _, bad := range []string{"../x", "a/b", `a\b`, "..", "", "a\x00b"} {
		if _, err := Store(root, bad, []byte("x"), "f"); !errors.Is(err, ErrBadID) {
			t.Errorf("engagement %q: %v", bad, err)
		}
		if _, err := storeWithID(root, "eng1", bad, []byte("x"), "f"); !errors.Is(err, ErrBadID) {
			t.Errorf("id %q: %v", bad, err)
		}
	}
	if _, err := Store(root, "eng1", make([]byte, MaxContentBytes+1), "f"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: %v", err)
	}
	if _, err := storeWithID(root, "eng1", "fixed", []byte("one"), "f"); err != nil {
		t.Fatal(err)
	}
	if _, err := storeWithID(root, "eng1", "fixed", []byte("two"), "f"); err == nil || !errors.Is(err, os.ErrExist) {
		t.Errorf("overwrite must fail: %v", err)
	}
	b, _ = os.ReadFile(filepath.Join(root, "inputs", "eng1", "fixed.bin"))
	if string(b) != "one" {
		t.Fatal("original overwritten")
	}
}
