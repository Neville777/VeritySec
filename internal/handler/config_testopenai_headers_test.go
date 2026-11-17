package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"veritysec/internal/config"
)

// TestTestOpenAIForwardsCustomHeaders verifies that "test connection" sends channel custom request headers just like a real conversation:
// static headers are sent as-is, %session_id% is filled with the probe value, and Authorization is still generated from api_key.
func TestTestOpenAIForwardsCustomHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var gotSession, gotFlag, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = r.Header.Get("X-Opencode-Session")
		gotFlag = r.Header.Get("X-Custom-Flag")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","model":"test-model","choices":[{"message":{"role":"assistant","content":"pong"}}]}`))
	}))
	defer srv.Close()

	h := &ConfigHandler{config: &config.Config{}, logger: zap.NewNop()}

	body := `{"provider":"openai","base_url":"` + srv.URL + `/v1","api_key":"test-key","model":"test-model",` +
		`"headers":{"X-Opencode-Session":"%session_id%","X-Custom-Flag":"hello"}}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/config/test-openai", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h.TestOpenAI(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["success"] != true {
		t.Fatalf("probe failed: %s", w.Body.String())
	}
	if gotSession != "connect-test" {
		t.Fatalf("X-Opencode-Session = %q, want connect-test", gotSession)
	}
	if gotFlag != "hello" {
		t.Fatalf("X-Custom-Flag = %q, want hello", gotFlag)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

// TestTestOpenAIWithoutHeadersKeepsBuiltinAuth confirms behavior is unchanged when headers are not configured.
func TestTestOpenAIWithoutHeadersKeepsBuiltinAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","choices":[{"message":{"role":"assistant","content":"pong"}}]}`))
	}))
	defer srv.Close()

	h := &ConfigHandler{config: &config.Config{}, logger: zap.NewNop()}
	body := `{"provider":"openai","base_url":"` + srv.URL + `/v1","api_key":"plain-key","model":"m"}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/config/test-openai", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h.TestOpenAI(c)

	if gotAuth != "Bearer plain-key" {
		t.Fatalf("Authorization = %q, want Bearer plain-key", gotAuth)
	}
}
