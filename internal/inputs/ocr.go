package inputs

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxOCRBytes caps the stored OCR text (200 KB).
const MaxOCRBytes = 200 << 10

// OCRTimeout bounds one tesseract run.
const OCRTimeout = 60 * time.Second

// ErrOCRUnavailable means tesseract is not on PATH.
var ErrOCRUnavailable = errors.New("inputs: tesseract not available")

// IsImageKind reports whether OCR applies to the kind.
func IsImageKind(k Kind) bool {
	switch k {
	case KindImagePNG, KindImageJPEG, KindImageGIF, KindImageWebP:
		return true
	}
	return false
}

// OCR runs `tesseract <path> stdout` (fixed argv, no shell, 60 s timeout) and returns the text
// capped at MaxOCRBytes. Nothing in the text is fetched or executed.
func OCR(path string) (string, error) {
	bin, err := exec.LookPath("tesseract")
	if err != nil {
		return "", ErrOCRUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), OCRTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, path, "stdout")
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, max: MaxOCRBytes}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("inputs: tesseract timed out")
		}
		return "", errors.New("inputs: tesseract failed")
	}
	b := out.Bytes()
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1] // trim a rune cut by the cap
	}
	return strings.ToValidUTF8(string(b), ""), nil
}

// limitedWriter keeps at most max bytes and discards the rest (never errors, so the process
// is not killed by a broken pipe).
type limitedWriter struct {
	w   *bytes.Buffer
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.max - l.w.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.w.Write(p[:room])
	}
	return len(p), nil
}
