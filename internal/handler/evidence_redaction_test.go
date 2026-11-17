package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const secretBody = "GET /login password=Hunter2secret\nAuthorization: Bearer abcdef1234567890xyz\ncontact bob@example.com"

type redactFixture struct {
	db    *database.DB
	h     *EngagementHandler
	store *database.EvidenceStore
	eng   string
	ev    *database.Evidence
}

func newRedactFixture(t *testing.T, created time.Time) *redactFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	db, err := database.NewDB(filepath.Join(dir, "r.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	eng, err := db.CreateEngagement(&database.Engagement{Name: "e"})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "evidence")
	h := NewEngagementHandler(db, root, zap.NewNop())
	store := &database.EvidenceStore{Root: root}
	ev := database.NewEvidenceRecord(eng.ID)
	ev.CreatedAt = created
	rel, sum, size, err := store.Save(eng.ID, ev.ID, []byte(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	ev.Kind, ev.Origin, ev.StoragePath, ev.SHA256, ev.SizeBytes = database.EvidenceNote, database.EvidenceOriginManual, rel, sum, size
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	return &redactFixture{db: db, h: h, store: store, eng: eng.ID, ev: ev}
}

func (f *redactFixture) get(perms map[string]bool, query string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x"+query, nil)
	c.Params = gin.Params{{Key: "id", Value: f.ev.ID}}
	c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Permissions: perms})
	f.h.GetEvidence(c)
	return w
}

func TestEvidenceReadRedactedCopyOriginalIntact(t *testing.T) {
	f := newRedactFixture(t, time.Now().UTC())
	w := f.get(map[string]bool{"project:read": true}, "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, s := range []string{"Hunter2secret", "abcdef1234567890xyz", "bob@example.com"} {
		if strings.Contains(body, s) {
			t.Fatalf("response leaks %q: %s", s, body)
		}
	}
	if !strings.Contains(body, "[REDACTED:password]") {
		t.Fatalf("no redaction tag: %s", body)
	}
	// The stored original is untouched and still matches the recorded sha256.
	data, err := f.store.Read(f.ev)
	if err != nil {
		t.Fatalf("integrity read failed: %v", err)
	}
	sum := sha256.Sum256(data)
	if string(data) != secretBody || hex.EncodeToString(sum[:]) != f.ev.SHA256 {
		t.Fatal("stored original changed")
	}
}

func TestEvidenceRawRefusedWithoutPermission(t *testing.T) {
	f := newRedactFixture(t, time.Now().UTC())
	if w := f.get(map[string]bool{"project:read": true}, "?raw=1"); w.Code != http.StatusForbidden {
		t.Fatalf("code %d", w.Code)
	}
	w := f.get(map[string]bool{"project:read": true, "project:write": true}, "?raw=1")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Hunter2secret") {
		t.Fatalf("raw with permission: %d %s", w.Code, w.Body.String())
	}
}

func TestPurgeKeepsRowAndShaReadReturns410(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	f := newRedactFixture(t, now.AddDate(0, 0, -40))
	// Retention 0: nothing happens.
	res, err := f.db.PurgeExpiredEvidence(f.store, 0, now)
	if err != nil || res.Purged != 0 {
		t.Fatalf("retention 0: %+v %v", res, err)
	}
	// Not yet expired.
	if res, _ = f.db.PurgeExpiredEvidence(f.store, 60, now); res.Purged != 0 {
		t.Fatalf("not expired: %+v", res)
	}
	r := gin.New()
	r.POST("/purge", f.h.PurgeEvidence)
	f.h.SetRetention(func() int { return 30 })
	f.h.now = func() time.Time { return now }
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/purge", nil))
	var out database.PurgeResult
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Purged != 1 || out.RetentionDays != 30 {
		t.Fatalf("purge: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(f.store.Root, filepath.FromSlash(f.ev.StoragePath))); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
	row, err := f.db.GetEvidence(f.ev.ID)
	if err != nil || !row.StorageDeleted || row.SHA256 != f.ev.SHA256 {
		t.Fatalf("row after purge: %+v %v", row, err)
	}
	g := f.get(map[string]bool{"project:read": true}, "")
	if g.Code != http.StatusGone || !strings.Contains(g.Body.String(), f.ev.SHA256) {
		t.Fatalf("read after purge: %d %s", g.Code, g.Body.String())
	}
	// Second run is a no-op.
	if res, _ = f.db.PurgeExpiredEvidence(f.store, 30, now); res.Purged != 0 {
		t.Fatalf("second run %+v", res)
	}
}

func TestVerifierExcerptHasNoSecrets(t *testing.T) {
	f := newVerifyFixture(t, true)
	store := f.h.evidenceStore
	eng, _ := f.db.GetEvidence(f.evID)
	ev := database.NewEvidenceRecord(eng.EngagementID)
	rel, sum, size, err := store.Save(eng.EngagementID, ev.ID, []byte(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	ev.Kind, ev.Origin, ev.StoragePath, ev.SHA256, ev.SizeBytes, ev.ToolExecutionID = database.EvidenceToolOutput, database.EvidenceOriginTool, rel, sum, size, "exec-2"
	if err := f.db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	if err := f.db.LinkClaimEvidence(f.claimID, ev.ID); err != nil {
		t.Fatal(err)
	}
	claims, err := f.h.buildVerifyClaims(f.fid)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range claims {
		for _, e := range c.Evidence {
			if e.ID != ev.ID {
				continue
			}
			found = true
			if e.SHA256 != sum {
				t.Fatal("hash must still describe the original")
			}
			for _, s := range []string{"Hunter2secret", "abcdef1234567890xyz", "bob@example.com"} {
				if strings.Contains(e.Excerpt, s) {
					t.Fatalf("excerpt leaks %q: %s", s, e.Excerpt)
				}
			}
			if !strings.Contains(e.Excerpt, "[REDACTED:") {
				t.Fatalf("excerpt: %s", e.Excerpt)
			}
		}
	}
	if !found {
		t.Fatal("evidence not in claims")
	}
}
