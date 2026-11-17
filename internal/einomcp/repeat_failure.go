package einomcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

const (
	// repeatedFailureLimit is the number of consecutive identical failures (same tool, same
	// normalised arguments, same error prefix) after which the tool is no longer executed.
	repeatedFailureLimit = 3
	// repeatedFailureErrChars is how much of the error text identifies "the same error".
	repeatedFailureErrChars = 120
)

type repeatFailureEntry struct {
	argsKey string
	errKey  string
	count   int
	lastErr string
}

// repeatFailureTracker is per run (it lives on the run's ConversationHolder). It keeps one entry per
// tool name, so a changed argument set for a tool replaces (resets) that tool's count and other
// tools are never affected.
type repeatFailureTracker struct {
	mu      sync.Mutex
	entries map[string]*repeatFailureEntry
}

// normalizeToolArgsKey returns a canonical JSON form of the arguments (object keys sorted by
// encoding/json), falling back to the trimmed raw string when it is not valid JSON.
func normalizeToolArgsKey(argumentsInJSON string) string {
	raw := strings.TrimSpace(argumentsInJSON)
	if raw == "" || raw == "null" {
		return "{}"
	}
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return string(b)
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// blocked reports whether this exact tool+args call has already failed repeatedFailureLimit times
// in a row; when true, msg is the tool error body to return without executing the tool.
func (t *repeatFailureTracker) blocked(toolName, argsKey string) (msg string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[toolName]
	if e == nil || e.argsKey != argsKey || e.count < repeatedFailureLimit {
		return "", false
	}
	return fmt.Sprintf("repeated identical failure stopped after %d attempts: %s", repeatedFailureLimit, e.lastErr), true
}

// record updates the tracker with the outcome of an executed call. errText is empty on success.
func (t *repeatFailureTracker) record(toolName, argsKey, errText string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[string]*repeatFailureEntry)
	}
	if strings.TrimSpace(errText) == "" {
		delete(t.entries, toolName)
		return
	}
	errText = strings.TrimSpace(errText)
	errKey := truncateRunes(errText, repeatedFailureErrChars)
	e := t.entries[toolName]
	if e != nil && e.argsKey == argsKey && e.errKey == errKey {
		e.count++
		e.lastErr = errKey
		return
	}
	t.entries[toolName] = &repeatFailureEntry{argsKey: argsKey, errKey: errKey, count: 1, lastErr: errKey}
}
