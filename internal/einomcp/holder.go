package einomcp

import "sync"

// ConversationHolder writes the session ID before each DeepAgent run, for use by the MCP tool bridge.
type ConversationHolder struct {
	mu sync.RWMutex
	id string

	// failures tracks repeated identical tool failures for this run (the holder is created once per run).
	failures repeatFailureTracker
}

func (h *ConversationHolder) Set(id string) {
	h.mu.Lock()
	h.id = id
	h.mu.Unlock()
}

func (h *ConversationHolder) Get() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.id
}
