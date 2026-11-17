package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"veritysec/internal/database"
	"veritysec/internal/mcp"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestGetStatsExecutionHealthBannerEqualsFailureClasses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "s.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	for i, r := range []struct{ status, err string }{
		{"completed", ""}, {"completed", ""}, {"failed", "request timed out"}, {"failed", "Payment Required"},
		{"failed", "crash"}, {"failed", "scope check refused"}, {"cancelled", ""},
	} {
		ex := &mcp.ToolExecution{ID: string(rune('a' + i)), ToolName: "t", Status: r.status, Error: r.err, StartTime: now, EndTime: &now}
		if err := db.SaveToolExecution(ex); err != nil {
			t.Fatal(err)
		}
	}
	h := NewMonitorHandler(nil, nil, db, zap.NewNop())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/monitor/stats", nil)
	c.Set(security.ContextSessionKey, security.Session{UserID: "u", Scope: database.RBACScopeAll})
	h.GetStats(c)
	var resp StatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	eh := resp.ExecutionHealth
	if eh == nil {
		t.Fatal("execution_health missing")
	}
	if eh.Success != 2 || eh.Timeout != 1 || eh.ProviderFailure != 1 || eh.ExecutionFailure != 1 || eh.PolicyRejected != 1 || eh.Cancelled != 1 {
		t.Fatalf("counts = %+v", eh)
	}
	if eh.FailedCount != eh.ExecutionFailure+eh.Timeout+eh.ProviderFailure {
		t.Fatalf("banner count %d != sum of failure classes", eh.FailedCount)
	}
	if eh.Denominator != 6 || resp.PolicyRejected != 1 || resp.CancelledCalls != 1 {
		t.Fatalf("denominator/policy = %+v %d", eh, resp.PolicyRejected)
	}
}
