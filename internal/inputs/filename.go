package inputs

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxFilenameBytes caps a sanitised name.
const MaxFilenameBytes = 255

// SanitizeFilename reduces a client-supplied name to a display-safe base name:
// path components (/ and \) are dropped, control characters and NUL removed,
// length capped at 255 bytes on a rune boundary. The result is for display and
// metadata only; it must never be used as a filesystem path.
func SanitizeFilename(name string) string {
	if !utf8.ValidString(name) {
		name = strings.ToValidUTF8(name, "")
	}
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r == 0 || unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "." || name == ".." {
		name = ""
	}
	if len(name) > MaxFilenameBytes {
		name = name[:MaxFilenameBytes]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	if name == "" {
		return "unnamed"
	}
	return name
}
