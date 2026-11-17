package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"veritysec/internal/database"
)

func (f *inFixture) scopedEngagement(scope string) string {
	b, _ := json.Marshal(map[string]interface{}{"name": "scoped", "scope_json": json.RawMessage(scope)})
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

func (f *inFixture) authorize(id string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest("POST", "/input-indicators/"+id+"/authorize", nil))
	return w
}

func indicatorFor(t *testing.T, inds []database.InputIndicator, value string) database.InputIndicator {
	for _, i := range inds {
		if i.Value == value {
			return i
		}
	}
	t.Fatalf("indicator %q not in %+v", value, inds)
	return database.InputIndicator{}
}

func TestAuthorizeIndicatorByScope(t *testing.T) {
	f := newInFixture(t)
	eid := f.scopedEngagement(`{"included":["10.1.2.3"]}`)
	w := f.upload(eid, "file", "n.txt", []byte("hosts 10.1.2.3 and 10.9.9.9\n"))
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	in := indicatorFor(t, r.Indicators, "10.1.2.3")
	out := indicatorFor(t, r.Indicators, "10.9.9.9")

	var resp struct {
		Decision  string                  `json:"decision"`
		Reason    string                  `json:"reason"`
		Indicator database.InputIndicator `json:"indicator"`
	}
	aw := f.authorize(in.ID)
	json.Unmarshal(aw.Body.Bytes(), &resp)
	if aw.Code != 200 || resp.Decision != "IN_SCOPE" || !resp.Indicator.Authorized || resp.Indicator.Status != "authorized" {
		t.Fatalf("in-scope: %d %s", aw.Code, aw.Body)
	}
	aw = f.authorize(out.ID)
	resp.Reason = ""
	json.Unmarshal(aw.Body.Bytes(), &resp)
	if aw.Code != 200 || resp.Decision != "OUT_OF_SCOPE" || resp.Reason == "" || resp.Indicator.Authorized || resp.Indicator.Status != "discovered" {
		t.Fatalf("out-of-scope: %d %s", aw.Code, aw.Body)
	}
	var n int
	f.db.QueryRow(`SELECT COUNT(*) FROM input_indicators WHERE authorized = 1`).Scan(&n)
	if n != 1 {
		t.Fatalf("authorized rows %d", n)
	}
	if w := f.authorize("missing"); w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
}

func TestAuthorizeIndicatorUnknownScope(t *testing.T) {
	f := newInFixture(t)
	eid := f.engagement("noscope") // empty scope: nothing is included
	w := f.upload(eid, "file", "n.txt", []byte("see 10.1.2.3\n"))
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	ind := indicatorFor(t, r.Indicators, "10.1.2.3")
	aw := f.authorize(ind.ID)
	var resp struct {
		Decision  string                  `json:"decision"`
		Indicator database.InputIndicator `json:"indicator"`
	}
	json.Unmarshal(aw.Body.Bytes(), &resp)
	if aw.Code != 200 || resp.Decision == "IN_SCOPE" || resp.Indicator.Authorized || resp.Indicator.Status != "discovered" {
		t.Fatalf("%d %s", aw.Code, aw.Body)
	}
	// An unparsable scope is UNKNOWN and stays discovered.
	f.db.Exec(`UPDATE engagements SET scope_json = '{bad' WHERE id = ?`, eid)
	aw = f.authorize(ind.ID)
	json.Unmarshal(aw.Body.Bytes(), &resp)
	if aw.Code != 200 || resp.Decision != "UNKNOWN" || resp.Indicator.Authorized {
		t.Fatalf("unparsable: %d %s", aw.Code, aw.Body)
	}
}

func TestAuthorizeIndicatorNeedsWrite(t *testing.T) {
	f := newInFixture(t)
	eid := f.scopedEngagement(`{"included":["10.1.2.3"]}`)
	var r uploadResp
	json.Unmarshal(f.upload(eid, "file", "n.txt", []byte("10.1.2.3\n")).Body.Bytes(), &r)
	f.perms = map[string]bool{"project:read": true}
	if w := f.authorize(r.Indicators[0].ID); w.Code != 403 {
		t.Fatalf("got %d", w.Code)
	}
	var n int
	f.db.QueryRow(`SELECT COUNT(*) FROM input_indicators WHERE authorized = 1`).Scan(&n)
	if n != 0 {
		t.Fatal("authorized without permission")
	}
}

var onePxPNG = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")

func TestImageOCRIndicators(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'login at http://ocr.example.com/admin'\n"
	if err := os.WriteFile(filepath.Join(dir, "tesseract"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	f := newInFixture(t)
	eid := f.engagement("ocr")
	w := f.upload(eid, "file", "shot.png", onePxPNG)
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	if w.Code != 200 || r.Input.DetectedKind != "image_png" || !strings.Contains(string(r.Input.Reasons), "ocr: ok") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	found := false
	for _, i := range r.Indicators {
		if strings.Contains(i.Value, "ocr.example.com") {
			found = true
			if i.Status != "discovered" || i.Authorized {
				t.Fatalf("bad %+v", i)
			}
		}
	}
	if !found {
		t.Fatalf("no OCR indicator: %+v", r.Indicators)
	}
	var txt string
	f.db.QueryRow(`SELECT ocr_text FROM engagement_inputs WHERE id = ?`, r.Input.ID).Scan(&txt)
	if !strings.Contains(txt, "ocr.example.com") {
		t.Fatalf("ocr_text %q", txt)
	}
}

func TestImageUploadWithoutTesseract(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	f := newInFixture(t)
	eid := f.engagement("noocr")
	w := f.upload(eid, "file", "shot.png", onePxPNG)
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	if w.Code != 200 || !strings.Contains(string(r.Input.Reasons), "ocr: unavailable") || len(r.Indicators) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestPcapUploadRecordsHeader(t *testing.T) {
	f := newInFixture(t)
	eid := f.engagement("pcap")
	b := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i := 0; i < 2; i++ {
		b = append(b, make([]byte, 8)...)
		b = append(b, 2, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb)
	}
	w := f.upload(eid, "file", "c.pcap", b)
	var r uploadResp
	json.Unmarshal(w.Body.Bytes(), &r)
	s := string(r.Input.Reasons)
	if w.Code != 200 || !strings.Contains(s, "packet_count=2") || !strings.Contains(s, "link_type=1") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
