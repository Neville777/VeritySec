package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func performRunWorkspaceRequest(user *database.RBACUser, messageID string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/runs/"+messageID+"/workspace", nil)
	c.Params = gin.Params{{Key: "messageId", Value: messageID}}
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      user.ID,
		Username:    user.Username,
		Permissions: map[string]bool{"chat:read": true},
		Scope:       database.RBACScopeAssigned,
	})
	handler(c)
	return w
}

// TestRunWorkspaceFollowsConversationAccess verifies the handler's own access check: a run for a
// conversation the caller cannot read comes back 404, and one the caller can read comes back 200
// with the expected top-level shape.
func TestRunWorkspaceFollowsConversationAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "run-workspace-rbac.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("operator1", "Operator One", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := db.CreateConversation("allowed", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := db.CreateConversation("hidden", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	allowedAssistant, err := db.AddMessage(allowed.ID, "assistant", "working", nil)
	if err != nil {
		t.Fatal(err)
	}
	hiddenAssistant, err := db.AddMessage(hidden.ID, "assistant", "working", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", allowed.ID); err != nil {
		t.Fatal(err)
	}

	h := NewRunHandler(db, zap.NewNop())

	w := performRunWorkspaceRequest(user, hiddenAssistant.ID, h.GetRunWorkspace)
	if w.Code != http.StatusNotFound {
		t.Fatalf("hidden conversation status = %d, want 404: %s", w.Code, w.Body.String())
	}

	w = performRunWorkspaceRequest(user, allowedAssistant.ID, h.GetRunWorkspace)
	if w.Code != http.StatusOK {
		t.Fatalf("allowed conversation status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Run struct {
			MessageID      string `json:"message_id"`
			ConversationID string `json:"conversation_id"`
			Status         string `json:"status"`
		} `json:"run"`
		Timeline []interface{} `json:"timeline"`
		Tools    []interface{} `json:"tools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Run.MessageID != allowedAssistant.ID || resp.Run.ConversationID != allowed.ID {
		t.Fatalf("unexpected run body: %+v", resp)
	}
	if resp.Run.Status != "running" {
		t.Fatalf("status = %q, want running", resp.Run.Status)
	}

	// An unknown message must also come back 404, not a 500.
	w = performRunWorkspaceRequest(user, "does-not-exist", h.GetRunWorkspace)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown message status = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestRunEventsEndpointAccessAndReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "run-events.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("operator2", "Operator Two", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	mine, _ := db.CreateConversation("mine", database.ConversationCreateMeta{})
	other, _ := db.CreateConversation("other", database.ConversationCreateMeta{})
	mineMsg, _ := db.AddMessage(mine.ID, "assistant", "x", nil)
	otherMsg, _ := db.AddMessage(other.ID, "assistant", "x", nil)
	if err := db.AssignResourceToUser(user.ID, "conversation", mine.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_ = db.AddProcessDetail(mineMsg.ID, mine.ID, "progress", "s", nil)
		_ = db.AddProcessDetail(otherMsg.ID, other.ID, "progress", "s", nil)
	}
	h := NewRunHandler(db, zap.NewNop())
	if w := performRunWorkspaceRequest(user, otherMsg.ID, h.GetRunEvents); w.Code != http.StatusNotFound {
		t.Fatalf("other user's message status = %d, want 404", w.Code)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/runs/"+mineMsg.ID+"/events?after_seq=2&limit=500", nil)
	c.Params = gin.Params{{Key: "messageId", Value: mineMsg.ID}}
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Permissions: map[string]bool{"chat:read": true}, Scope: database.RBACScopeAssigned})
	h.GetRunEvents(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Events  []struct{ Seq int64 } `json:"events"`
		NextSeq int64                 `json:"next_seq"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Events) != 2 || resp.Events[0].Seq != 3 || resp.NextSeq != 4 {
		t.Fatalf("unexpected: %s", w.Body.String())
	}
}
