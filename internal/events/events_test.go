package events

import (
	"testing"
	"time"
)

func recv(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(time.Second):
		return nil
	}
}

func TestOwnerOnlyAndPermissionScoped(t *testing.T) {
	alice, cancelA := Subscribe("alice", map[string]bool{})
	defer cancelA()
	admin, cancelAdmin := Subscribe("root", map[string]bool{"config:read": true})
	defer cancelAdmin()
	bob, cancelB := Subscribe("bob", map[string]bool{})
	defer cancelB()

	Publish(Event{Topic: "hitl.pending", OwnerID: "alice", Data: map[string]string{"id": "1"}})
	if recv(t, alice) == nil {
		t.Fatal("owner did not receive their event")
	}
	if recv(t, bob) != nil {
		t.Fatal("another user received someone else's event")
	}
	Publish(Event{Topic: "tools.install", Permission: "config:read"})
	if recv(t, admin) == nil {
		t.Fatal("permitted user did not receive a permission-scoped event")
	}
	if recv(t, alice) != nil {
		t.Fatal("user without the permission received a permission-scoped event")
	}
}

func TestUnscopedEventIsDropped(t *testing.T) {
	ch, cancel := Subscribe("alice", map[string]bool{"config:read": true})
	defer cancel()
	Publish(Event{Topic: "nobody"})
	if recv(t, ch) != nil {
		t.Fatal("an event with no owner or permission must not be delivered")
	}
}
