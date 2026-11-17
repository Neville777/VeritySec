package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type inFixture struct {
	t      *testing.T
	db     *database.DB
	router *gin.Engine
	data   string
	perms  map[string]bool
}

func newInFixture(t *testing.T) *inFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	data := t.TempDir()
	db, err := database.NewDB(filepath.Join(data, "x.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := NewEngagementHandler(db, filepath.Join(data, "evidence"), zap.NewNop())
	f := &inFixture{t: t, db: db, data: data, perms: map[string]bool{"project:read": true, "project:write": true}}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Scope: database.RBACScopeAll, Permissions: f.perms})
		c.Next()
	})
	r.POST("/engagements", h.CreateEngagement)
	r.POST("/engagements/:id/inputs", h.UploadInput)
	r.GET("/engagements/:id/inputs", h.ListInputs)
	r.POST("/input-indicators/:id/authorize", h.AuthorizeInputIndicator)
	r.GET("/engagements/:id/inputs/:inputId/indicators", h.ListInputIndicators)
	f.router = r
	return f
}

func (f *inFixture) engagement(name string) string {
	b, _ := json.Marshal(map[string]string{"name": name})
	req := httptest.NewRequest("POST", "/engagements", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	var e database.Engagement
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if e.ID == "" {
		f.t.Fatalf("create engagement: %d %s", w.Code, w.Body)
	}
	return e.ID
}

func (f *inFixture) upload(eid, field, name string, content []byte) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if name != "" {
		fw, _ := mw.CreateFormFile(field, name)
		fw.Write(content)
	}
	mw.Close()
	req := httptest.NewRequest("POST", "/engagements/"+eid+"/inputs", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *inFixture) get(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

type uploadResp struct {
	Input      database.EngagementInput  `json:"input"`
	Indicators []database.InputIndicator `json:"indicators"`
}

func TestUploadStoresFileAndIndicators(t *testing.T) {
	f := newInFixture(t)
	eid := f.engagement("e1")
	content := []byte("notes: https://app.example.com/login and 10.1.2.3 and 10.9.0.0/16\n")
	w := f.upload(eid, "file", "../notes.txt", content)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	sum := sha256.Sum256(content)
	if r.Input.SHA256 != hex.EncodeToString(sum[:]) || r.Input.OriginalName != "notes.txt" || r.Input.Size != int64(len(content)) {
		t.Fatalf("%+v", r.Input)
	}
	p := filepath.Join(f.data, "inputs", eid, r.Input.ID+".bin")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v %v", st, err)
	}
	b, _ := os.ReadFile(p)
	if !bytes.Equal(b, content) {
		t.Fatal("stored bytes differ")
	}
	if strings.Contains(w.Body.String(), "storage_path") || strings.Contains(w.Body.String(), f.data) {
		t.Fatal("storage path leaked")
	}
	if len(r.Indicators) < 4 {
		t.Fatalf("indicators %+v", r.Indicators)
	}
	for _, i := range r.Indicators {
		if i.Status != "discovered" || i.Authorized {
			t.Fatalf("bad indicator %+v", i)
		}
	}
	var n int
	f.db.QueryRow(`SELECT COUNT(*) FROM input_indicators WHERE authorized != 0 OR status != 'discovered'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d authorized rows", n)
	}
	lw := f.get("/engagements/" + eid + "/inputs/" + r.Input.ID + "/indicators")
	var lr struct {
		Indicators []database.InputIndicator `json:"indicators"`
	}
	json.Unmarshal(lw.Body.Bytes(), &lr)
	if lw.Code != 200 || len(lr.Indicators) != len(r.Indicators) {
		t.Fatalf("%d %s", lw.Code, lw.Body)
	}
}

func TestUploadFakePNGMismatch(t *testing.T) {
	f := newInFixture(t)
	eid := f.engagement("e1")
	w := f.upload(eid, "file", "evil.png", []byte("just text http://x.example.org"))
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	if w.Code != 200 || r.Input.DetectedKind != "text_utf8" || !strings.Contains(string(r.Input.Reasons), "mismatch") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUploadRefusals(t *testing.T) {
	f := newInFixture(t)
	eid := f.engagement("e1")
	if w := f.upload(eid, "file", "", nil); w.Code != 400 {
		t.Fatalf("missing file: %d", w.Code)
	}
	if w := f.upload(eid, "other", "a.txt", []byte("x")); w.Code != 400 {
		t.Fatalf("wrong field: %d", w.Code)
	}
	if w := f.upload(eid, "file", "big.bin", make([]byte, 25<<20+1)); w.Code != 413 {
		t.Fatalf("oversize: %d", w.Code)
	}
	if w := f.upload("nope", "file", "a.txt", []byte("x")); w.Code != 404 {
		t.Fatalf("unknown engagement: %d", w.Code)
	}
	f.perms = map[string]bool{"project:read": true}
	if w := f.upload(eid, "file", "a.txt", []byte("x")); w.Code != 403 {
		t.Fatalf("no write: %d", w.Code)
	}
	f.perms = map[string]bool{}
	if w := f.get("/engagements/" + eid + "/inputs"); w.Code != 403 {
		t.Fatalf("no read: %d", w.Code)
	}
}

func TestInputsIsolatedPerEngagement(t *testing.T) {
	f := newInFixture(t)
	a, b := f.engagement("a"), f.engagement("b")
	w := f.upload(a, "file", "a.txt", []byte("host a.example.com"))
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	var lb struct {
		Inputs []database.EngagementInput `json:"inputs"`
	}
	json.Unmarshal(f.get("/engagements/"+b+"/inputs").Body.Bytes(), &lb)
	if len(lb.Inputs) != 0 {
		t.Fatalf("leak: %+v", lb)
	}
	if w := f.get("/engagements/" + b + "/inputs/" + r.Input.ID + "/indicators"); w.Code != 404 {
		t.Fatalf("cross-engagement indicators: %d", w.Code)
	}
	var la struct {
		Inputs []database.EngagementInput `json:"inputs"`
	}
	json.Unmarshal(f.get("/engagements/"+a+"/inputs").Body.Bytes(), &la)
	if len(la.Inputs) != 1 {
		t.Fatalf("%+v", la)
	}
}
