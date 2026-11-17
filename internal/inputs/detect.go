// Package inputs records user-supplied engagement material safely and extracts
// URLs, hostnames and IPs from it. Nothing here executes, fetches, decompresses,
// parses archives, or sends anything anywhere. File type comes from the bytes,
// never from the client-claimed name or from a model.
package inputs

import (
	"bytes"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"
)

// Kind is the detected content type.
type Kind string

const (
	KindImagePNG      Kind = "image_png"
	KindImageJPEG     Kind = "image_jpeg"
	KindImageGIF      Kind = "image_gif"
	KindImageWebP     Kind = "image_webp"
	KindPDF           Kind = "pdf"
	KindZip           Kind = "zip"
	KindGzip          Kind = "gzip"
	KindPcap          Kind = "pcap"
	KindPcapng        Kind = "pcapng"
	KindTextUTF8      Kind = "text_utf8"
	KindTextLogLike   Kind = "text_log_like"
	KindSourceCode    Kind = "source_code"
	KindBinaryUnknown Kind = "binary_unknown"
)

// Detection is the result of Detect.
type Detection struct {
	Kind       Kind
	MIME       string
	Confidence float64 // 0..1
	Reasons    []string
}

// extension -> kinds that extension legitimately implies.
var extKinds = map[string][]Kind{
	"png": {KindImagePNG}, "jpg": {KindImageJPEG}, "jpeg": {KindImageJPEG},
	"gif": {KindImageGIF}, "webp": {KindImageWebP}, "pdf": {KindPDF},
	"zip": {KindZip}, "gz": {KindGzip}, "tgz": {KindGzip},
	"pcap": {KindPcap}, "pcapng": {KindPcapng},
}

var sourceExts = map[string]bool{
	"go": true, "py": true, "js": true, "ts": true, "java": true, "c": true, "h": true,
	"cpp": true, "cc": true, "hpp": true, "rs": true, "rb": true, "php": true, "sh": true,
	"cs": true, "swift": true, "kt": true, "pl": true, "lua": true, "sql": true,
}

func ext(name string) string {
	e := strings.ToLower(path.Ext(SanitizeFilename(name)))
	return strings.TrimPrefix(e, ".")
}

// Detect classifies content using magic bytes first. claimedName only produces
// extra reasons (mismatch warnings) and the lower-confidence source_code hint.
func Detect(content []byte, claimedName string) Detection {
	d := detectBytes(content)
	e := ext(claimedName)

	if want, ok := extKinds[e]; ok {
		match := false
		for _, k := range want {
			if k == d.Kind {
				match = true
			}
		}
		if match {
			d.Reasons = append(d.Reasons, "claimed extension ."+e+" agrees with content")
		} else {
			d.Reasons = append(d.Reasons, "mismatch: claimed extension ."+e+" but content detected as "+string(d.Kind)+"; claim not trusted")
			if d.Confidence > 0.6 {
				d.Confidence = 0.6
			}
		}
	}

	if sourceExts[e] && (d.Kind == KindTextUTF8 || d.Kind == KindTextLogLike) {
		d.Kind = KindSourceCode
		d.MIME = "text/plain; charset=utf-8"
		d.Confidence = 0.5
		d.Reasons = append(d.Reasons, "source_code inferred from extension ."+e+" plus text heuristic (low confidence)")
	}
	return d
}

func detectBytes(c []byte) Detection {
	mk := func(k Kind, mime, why string) Detection {
		return Detection{Kind: k, MIME: mime, Confidence: 0.95, Reasons: []string{why}}
	}
	if len(c) == 0 {
		return Detection{Kind: KindBinaryUnknown, MIME: "application/octet-stream", Confidence: 0.1, Reasons: []string{"empty content"}}
	}
	// PCAP family first: net/http does not know these.
	if len(c) >= 4 {
		switch {
		case bytes.HasPrefix(c, []byte{0x0a, 0x0d, 0x0d, 0x0a}):
			return mk(KindPcapng, "application/vnd.tcpdump.pcap", "pcapng magic 0a0d0d0a")
		case bytes.HasPrefix(c, []byte{0xa1, 0xb2, 0xc3, 0xd4}), bytes.HasPrefix(c, []byte{0xd4, 0xc3, 0xb2, 0xa1}),
			bytes.HasPrefix(c, []byte{0xa1, 0xb2, 0x3c, 0x4d}), bytes.HasPrefix(c, []byte{0x4d, 0x3c, 0xb2, 0xa1}):
			return mk(KindPcap, "application/vnd.tcpdump.pcap", "pcap magic bytes")
		}
	}
	head := c
	if len(head) > 512 {
		head = head[:512]
	}
	switch http.DetectContentType(head) {
	case "image/png":
		return mk(KindImagePNG, "image/png", "PNG signature")
	case "image/jpeg":
		return mk(KindImageJPEG, "image/jpeg", "JPEG signature")
	case "image/gif":
		return mk(KindImageGIF, "image/gif", "GIF signature")
	case "image/webp":
		return mk(KindImageWebP, "image/webp", "RIFF/WEBP signature")
	case "application/pdf":
		return mk(KindPDF, "application/pdf", "%PDF- signature")
	case "application/zip":
		return mk(KindZip, "application/zip", "PK zip signature (not opened)")
	case "application/x-gzip":
		return mk(KindGzip, "application/gzip", "gzip signature (not decompressed)")
	}
	// Empty zip has only an end-of-central-directory record.
	if bytes.HasPrefix(c, []byte("PK\x05\x06")) {
		return mk(KindZip, "application/zip", "PK empty zip signature (not opened)")
	}
	return detectText(c)
}

func detectText(c []byte) Detection {
	sample := c
	if len(sample) > 64*1024 {
		sample = sample[:64*1024]
		// avoid cutting a rune in half
		for len(sample) > 0 && !utf8.Valid(sample) && len(c) > len(sample) {
			sample = sample[:len(sample)-1]
		}
	}
	bin := Detection{Kind: KindBinaryUnknown, MIME: "application/octet-stream", Confidence: 0.5}
	if bytes.IndexByte(sample, 0) >= 0 {
		bin.Reasons = []string{"contains NUL bytes; no known signature"}
		return bin
	}
	if !utf8.Valid(sample) {
		bin.Reasons = []string{"not valid UTF-8; no known signature"}
		return bin
	}
	ctrl := 0
	for _, r := range string(sample) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			ctrl++
		}
	}
	if ctrl*50 > len(sample) { // >2% control chars
		bin.Reasons = []string{"high control-character ratio; no known signature"}
		return bin
	}
	if looksLogLike(string(sample)) {
		return Detection{Kind: KindTextLogLike, MIME: "text/plain; charset=utf-8", Confidence: 0.7,
			Reasons: []string{"valid UTF-8 text with timestamp/level-prefixed lines"}}
	}
	return Detection{Kind: KindTextUTF8, MIME: "text/plain; charset=utf-8", Confidence: 0.8,
		Reasons: []string{"valid UTF-8 text, no binary markers"}}
}

func looksLogLike(s string) bool {
	lines := strings.Split(s, "\n")
	n, hit := 0, 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		n++
		if n > 50 {
			break
		}
		if logLine(l) {
			hit++
		}
	}
	return n >= 3 && hit*2 >= n
}

func logLine(l string) bool {
	// leading timestamp: 2024-01-02, 2024/01/02, Jan  2 15:04:05, [..., or HH:MM:SS
	if len(l) >= 10 && l[0] >= '0' && l[0] <= '9' && (l[4] == '-' || l[4] == '/') {
		return true
	}
	if len(l) >= 8 && l[2] == ':' && l[5] == ':' {
		return true
	}
	if len(l) > 0 && l[0] == '[' {
		return true
	}
	u := strings.ToUpper(l)
	for _, lv := range []string{"INFO", "WARN", "ERROR", "DEBUG", "TRACE", "FATAL"} {
		if strings.Contains(u[:min(len(u), 40)], lv) {
			return true
		}
	}
	for _, m := range []string{"Jan ", "Feb ", "Mar ", "Apr ", "May ", "Jun ", "Jul ", "Aug ", "Sep ", "Oct ", "Nov ", "Dec "} {
		if strings.HasPrefix(l, m) {
			return true
		}
	}
	return false
}
