package handler

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestAssetRelationshipRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "g.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := NewEngagementHandler(db, t.TempDir(), zap.NewNop())
	build := func(perms map[string]bool) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Scope: database.RBACScopeAll, Permissions: perms})
		})
		r.GET("/engagements/:id/asset-graph", h.GetAssetGraph)
		r.POST("/engagements/:id/asset-relationships", h.CreateAssetRelationship)
		r.PUT("/asset-relationships/:id", h.UpdateAssetRelationship)
		return r
	}
	writer, reader := build(map[string]bool{"project:write": true}), build(map[string]bool{"project:read": true})
	e, _ := db.CreateEngagement(&database.Engagement{Name: "Acme"})
	mk := func(host string) string {
		a := &database.Asset{Host: host}
		if _, err := db.UpsertAssets([]*database.Asset{a}, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.JoinAssetToEngagement(e.ID, a.ID, false); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	a, b := mk("a.example.com"), mk("b.example.com")
	base := "/engagements/" + e.ID

	w := doReq(writer, "POST", base+"/asset-relationships", map[string]string{"from_asset_id": a, "to_asset_id": b, "relation_type": "CONNECTS_TO"})
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var rel database.AssetRelationship
	json.Unmarshal(w.Body.Bytes(), &rel)
	if rel.Confidence != "manual" || rel.CreatedBy != "u1" {
		t.Fatalf("manual default: %+v", rel)
	}
	if w = doReq(writer, "POST", base+"/asset-relationships", map[string]string{"from_asset_id": a, "to_asset_id": b, "relation_type": "NOPE"}); w.Code != 400 {
		t.Fatalf("bad type: %d", w.Code)
	}
	if w = doReq(writer, "PUT", "/asset-relationships/"+rel.ID, map[string]string{"confidence": "verified"}); w.Code != 400 {
		t.Fatalf("verified without reason: %d", w.Code)
	}
	if w = doReq(reader, "PUT", "/asset-relationships/"+rel.ID, map[string]string{"confidence": "verified", "reason": "checked"}); w.Code != 400 {
		t.Fatalf("verified without project:write: %d", w.Code)
	}
	if w = doReq(writer, "PUT", "/asset-relationships/"+rel.ID, map[string]string{"confidence": "verified", "reason": "checked"}); w.Code != 200 {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	if w = doReq(writer, "PUT", "/asset-relationships/missing", map[string]string{"confidence": "inferred"}); w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
	w = doReq(reader, "GET", base+"/asset-graph", nil)
	var g database.AssetGraph
	json.Unmarshal(w.Body.Bytes(), &g)
	if w.Code != 200 || len(g.Nodes) != 2 || len(g.Edges) != 1 || g.Edges[0].Confidence != "verified" {
		t.Fatalf("graph: %d %s", w.Code, w.Body.String())
	}
	if w = doReq(reader, "GET", "/engagements/nope/asset-graph", nil); w.Code != 404 {
		t.Fatalf("unknown engagement: %d", w.Code)
	}
}
