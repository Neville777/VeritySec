// Package events is a small in-process publish/subscribe hub that pushes real-time
// updates to browser clients over one WebSocket.
//
// Every event is delivered only to subscribers that are allowed to see it:
//   - an event with an OwnerID goes to that user only;
//   - an event with a Permission goes to users who hold that permission;
//   - an event with neither is delivered to nobody (events must name a scope).
package events

import (
	"encoding/json"
	"sync"
)

// Event is one update. Data must not contain secrets; clients fetch details through the authorized REST API.
type Event struct {
	Topic      string      `json:"topic"`
	Data       interface{} `json:"data,omitempty"`
	OwnerID    string      `json:"-"`
	Permission string      `json:"-"`
}

type subscriber struct {
	ch          chan []byte
	userID      string
	permissions map[string]bool
}

var (
	mu   sync.Mutex
	subs = map[*subscriber]struct{}{}
)

// Subscribe registers a client for the events it is allowed to see. The returned cancel must be called when the client goes away.
func Subscribe(userID string, permissions map[string]bool) (<-chan []byte, func()) {
	s := &subscriber{ch: make(chan []byte, 64), userID: userID, permissions: permissions}
	mu.Lock()
	subs[s] = struct{}{}
	mu.Unlock()
	cancel := func() {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := subs[s]; ok {
			delete(subs, s)
			close(s.ch)
		}
	}
	return s.ch, cancel
}

// Publish sends ev to every subscriber allowed to see it. It never blocks: a slow client drops events.
func Publish(ev Event) {
	if ev.OwnerID == "" && ev.Permission == "" {
		return
	}
	msg, err := json.Marshal(ev)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for s := range subs {
		allowed := (ev.OwnerID != "" && s.userID == ev.OwnerID) ||
			(ev.Permission != "" && s.permissions[ev.Permission])
		if !allowed {
			continue
		}
		select {
		case s.ch <- msg:
		default:
		}
	}
}
