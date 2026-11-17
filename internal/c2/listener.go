package c2

import (
	"strings"
	"sync"

	"veritysec/internal/database"

	"go.uber.org/zap"
)

// Listener is the abstraction for every transport (TCP/HTTP/HTTPS/WS/DNS);
// Manager is unaware of concrete implementations and creates them via ListenerRegistry.
type Listener interface {
	// Type returns the listener's type string (e.g. "tcp_reverse")
	Type() string
	// Start begins listening; should return ErrPortInUse if the port is occupied
	Start() error
	// Stop stops listening and releases all related goroutines (must not panic)
	Stop() error
}

// ListenerCreationCtx is the context passed to the factory when initializing a listener
type ListenerCreationCtx struct {
	Listener *database.C2Listener
	Config   *ListenerConfig
	Manager  *Manager
	Logger   *zap.Logger
}

// ListenerFactory creates a listener instance; the returned instance has not been started yet
type ListenerFactory func(ctx ListenerCreationCtx) (Listener, error)

// ListenerRegistry maps type -> factory; concrete implementations are registered by
// internal/app at startup, and tests can inject mock factories to override them.
type ListenerRegistry struct {
	mu        sync.RWMutex
	factories map[string]ListenerFactory
}

// NewListenerRegistry creates an empty registry
func NewListenerRegistry() *ListenerRegistry {
	return &ListenerRegistry{factories: make(map[string]ListenerFactory)}
}

// Register registers a listener factory
func (r *ListenerRegistry) Register(typeName string, f ListenerFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[strings.ToLower(strings.TrimSpace(typeName))] = f
}

// Get returns the factory; nil means not registered
func (r *ListenerRegistry) Get(typeName string) ListenerFactory {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.factories[strings.ToLower(strings.TrimSpace(typeName))]
}

// RegisteredTypes lists the registered types, used for frontend enumeration
func (r *ListenerRegistry) RegisteredTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for k := range r.factories {
		out = append(out, k)
	}
	return out
}
