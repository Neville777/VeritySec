package handler

import (
	"strings"
	"testing"
	"time"

	"veritysec/internal/database"
)

func TestApprovalEndpoints(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAll)
	f.router.GET("/engagements/:id/approvals", NewEngagementHandler(f.db, f.root, nil).ListApprovals)
	h := NewEngagementHandler(f.db, f.root, nil)
	f.router.POST("/approval-requests/:id/decision", h.DecideApproval)

	var e database.Engagement
	if code := f.json("POST", "/engagements", map[string]interface{}{"name": "A"}, &e); code != 200 {
		t.Fatal(code)
	}
	now := time.Now()
	r1, _, err := f.db.RequestApproval(e.ID, "c", "m", "probe", "a.example.com", "h1", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r2, _, _ := f.db.RequestApproval(e.ID, "c", "m", "probe", "b.example.com", "h2", now.Add(-time.Minute), time.Hour)
	if _, err := f.db.DecideApproval(r2.ID, false, "u", "no", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Approvals []database.ApprovalRequest `json:"approvals"`
	}
	if code := f.json("GET", "/engagements/"+e.ID+"/approvals", nil, &list); code != 200 || len(list.Approvals) != 2 || list.Approvals[0].ID != r1.ID {
		t.Fatalf("list: %d %+v", code, list)
	}
	base := "/approval-requests/" + r1.ID + "/decision"
	if code := f.json("POST", base, map[string]string{"decision": "maybe"}, nil); code != 400 {
		t.Fatalf("bad decision: %d", code)
	}
	if code := f.json("POST", base, map[string]string{"decision": "deny"}, nil); code != 400 {
		t.Fatalf("deny without reason: %d", code)
	}
	if code := f.json("POST", "/approval-requests/nope/decision", map[string]string{"decision": "approve"}, nil); code != 404 {
		t.Fatalf("unknown: %d", code)
	}
	var out struct {
		Approval database.ApprovalRequest `json:"approval"`
	}
	if code := f.json("POST", base, map[string]string{"decision": "approve", "reason": "ok"}, &out); code != 200 || out.Approval.Status != "approved" || out.Approval.DecidedBy != "u1" {
		t.Fatalf("approve: %d %+v", code, out)
	}
	if code := f.json("POST", base, map[string]string{"decision": "approve"}, nil); code != 409 {
		t.Fatalf("second decision: %d", code)
	}
	if ok, _ := f.db.ConsumeApproval(e.ID, "probe", "a.example.com", "h1", time.Now()); !ok {
		t.Fatal("approved request should be consumable")
	}
	if strings.Contains(f.do("GET", "/engagements/"+e.ID+"/approvals", "", nil).Body.String(), "arguments\"") {
		t.Fatal("arguments leaked")
	}
}
