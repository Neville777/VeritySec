package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
)

func recipes() []config.ToolConfig {
	return []config.ToolConfig{
		{Name: "zeta", Command: "zeta", Enabled: true},
		{Name: "alpha", Command: "nmap", Enabled: false, Parameters: []config.ParameterConfig{
			{Name: "url", Type: "string", Required: true}, {Name: "n", Type: "int"}}},
	}
}

func TestTargetRequiredFromURL(t *testing.T) {
	got := BuildRegistry(recipes(), Options{})
	if !got[0].TargetRequired || got[1].TargetRequired {
		t.Fatalf("target flags: %+v", got)
	}
}

func TestNoParametersEmptySchema(t *testing.T) {
	s := BuildRegistry(recipes(), Options{})[1].InputSchema
	if _, ok := s["required"]; ok || len(s["properties"].(map[string]interface{})) != 0 {
		t.Fatalf("schema not empty: %v", s)
	}
}

func TestDisabledListedAndSorted(t *testing.T) {
	got := BuildRegistry(recipes(), Options{TimeoutSeconds: 5, OutputLimitBytes: 7})
	if len(got) != 2 || got[0].Name != "alpha" || got[0].Enabled || got[0].TimeoutSeconds != 5 || got[0].OutputLimitBytes != 7 {
		t.Fatalf("unexpected: %+v", got)
	}
	if got[1].RiskCategory != RiskUnknown || got[0].RequiredPermission != "chat:write" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestDeterministic(t *testing.T) {
	if !reflect.DeepEqual(BuildRegistry(recipes(), Options{}), BuildRegistry(recipes(), Options{})) {
		t.Fatal("builds differ")
	}
}

// The handler lives in internal/handler; this test checks the RBAC mapping the route relies on.
func TestRegistryEndpointPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for perm, want := range map[string]int{"config:read": 200, "chat:read": 403} {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set(security.ContextSessionKey, security.Session{UserID: "u", Permissions: map[string]bool{perm: true}, Scope: database.RBACScopeAll})
		})
		r.Use(security.RBACMiddleware(&database.DB{}))
		r.GET("/api/tools/registry", func(c *gin.Context) {
			c.JSON(200, gin.H{"tools": BuildRegistry(recipes(), Options{})})
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/tools/registry", nil))
		if w.Code != want {
			t.Fatalf("%s: got %d want %d", perm, w.Code, want)
		}
		if want == 200 {
			var body struct{ Tools []ToolSpec }
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Tools) != 2 {
				t.Fatalf("bad body %s", w.Body.String())
			}
		}
	}
}
