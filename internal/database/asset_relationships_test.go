package database

import (
	"errors"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

type relFixture struct {
	db  *DB
	eng string
}

func newRelFixture(t *testing.T) *relFixture {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "r.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e, err := db.CreateEngagement(&Engagement{Name: "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	return &relFixture{db: db, eng: e.ID}
}

func (f *relFixture) asset(t *testing.T, eng, host, ip, domain string) string {
	t.Helper()
	a := &Asset{Host: host, IP: ip, Domain: domain}
	if _, err := f.db.UpsertAssets([]*Asset{a}, ""); err != nil {
		t.Fatal(err)
	}
	if eng != "" {
		if err := f.db.JoinAssetToEngagement(eng, a.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	return a.ID
}

func (f *relFixture) evidence(t *testing.T, eng string) string {
	t.Helper()
	ev := NewEvidenceRecord(eng)
	ev.Kind, ev.StoragePath, ev.SHA256 = EvidenceOther, "x", "00"
	if err := f.db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

func TestRelationshipConfidenceRules(t *testing.T) {
	f := newRelFixture(t)
	a, b := f.asset(t, f.eng, "a.example.com", "", ""), f.asset(t, f.eng, "b.example.com", "", "")
	in := func(conf string) AssetRelationshipInput {
		return AssetRelationshipInput{EngagementID: f.eng, FromAssetID: a, ToAssetID: b, RelationType: RelConnectsTo, Confidence: conf}
	}
	wantRule := func(name string, _ *AssetRelationship, err error) {
		t.Helper()
		if !errors.Is(err, ErrRelationshipRule) {
			t.Fatalf("%s: want rule refusal, got %v", name, err)
		}
	}

	// verified: needs reason and project:write.
	v := in(ConfVerified)
	v.Human, v.CanVerify = true, true
	r, err := f.db.UpsertAssetRelationship(v)
	wantRule("verified without reason", r, err)
	v.Reason, v.CanVerify = "confirmed with nmap", false
	r, err = f.db.UpsertAssetRelationship(v)
	wantRule("verified without project:write", r, err)

	// observed: needs evidence or tool execution; evidence must be this engagement's.
	r, err = f.db.UpsertAssetRelationship(in(ConfObserved))
	wantRule("observed without provenance", r, err)
	other, _ := f.db.CreateEngagement(&Engagement{Name: "Other"})
	foreign := f.evidence(t, other.ID)
	o := in(ConfObserved)
	o.EvidenceID = foreign
	r, err = f.db.UpsertAssetRelationship(o)
	wantRule("observed with foreign evidence", r, err)
	o.EvidenceID = "missing"
	r, err = f.db.UpsertAssetRelationship(o)
	wantRule("observed with unknown evidence", r, err)

	// manual: only a person.
	r, err = f.db.UpsertAssetRelationship(in(ConfManual))
	wantRule("manual by a tool", r, err)

	// valid observed with own evidence, then upgrade to verified, then downgrade rules.
	o.EvidenceID = f.evidence(t, f.eng)
	o.Confidence = ConfObserved
	rel, err := f.db.UpsertAssetRelationship(o)
	if err != nil || rel.Confidence != ConfObserved || rel.EvidenceID != o.EvidenceID {
		t.Fatalf("observed: %+v %v", rel, err)
	}
	v.Reason, v.CanVerify = "confirmed with nmap", true
	rel, err = f.db.UpsertAssetRelationship(v)
	if err != nil || rel.Confidence != ConfVerified || rel.Reason == "" {
		t.Fatalf("upgrade: %+v %v", rel, err)
	}
	tool := in(ConfInferred)
	r, err = f.db.UpsertAssetRelationship(tool)
	wantRule("downgrade by a tool", r, err)
	tool = in(ConfObserved)
	tool.ToolExecutionID = "exec-1"
	r, err = f.db.UpsertAssetRelationship(tool)
	wantRule("downgrade verified to observed by a tool", r, err)
	// A person may downgrade.
	h := in(ConfInferred)
	h.Human = true
	rel, err = f.db.UpsertAssetRelationship(h)
	if err != nil || rel.Confidence != ConfInferred {
		t.Fatalf("human downgrade: %+v %v", rel, err)
	}
	// Assets of another engagement are refused.
	x := f.asset(t, other.ID, "x.example.com", "", "")
	bad := in(ConfInferred)
	bad.ToAssetID = x
	r, err = f.db.UpsertAssetRelationship(bad)
	wantRule("cross-engagement asset", r, err)
}

func TestToolAssetSaveCreatesObservedResolvesTo(t *testing.T) {
	f := newRelFixture(t)
	ipAsset := f.asset(t, f.eng, "", "10.0.0.5", "")
	zone := f.asset(t, f.eng, "", "", "example.com")
	host := f.asset(t, f.eng, "", "10.0.0.5", "www.example.com")

	if err := f.db.RecordObservedAssetEdges(host, ""); err != nil {
		t.Fatal(err)
	}
	if g, _ := f.db.ListAssetGraph(f.eng); len(g.Edges) != 0 {
		t.Fatalf("edges without a tool execution id: %+v", g.Edges)
	}
	if err := f.db.RecordObservedAssetEdges(host, "exec-42"); err != nil {
		t.Fatal(err)
	}
	g, err := f.db.ListAssetGraph(f.eng)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]AssetRelationship{}
	for _, e := range g.Edges {
		got[e.RelationType] = e
	}
	rt, ok := got[RelResolvesTo]
	if !ok || rt.FromAssetID != host || rt.ToAssetID != ipAsset || rt.Confidence != ConfObserved || rt.ToolExecutionID != "exec-42" {
		t.Fatalf("RESOLVES_TO: %+v", g.Edges)
	}
	sd, ok := got[RelSubdomainOf]
	if !ok || sd.FromAssetID != host || sd.ToAssetID != zone || sd.Confidence != ConfObserved {
		t.Fatalf("SUBDOMAIN_OF: %+v", g.Edges)
	}
	// Re-saving is idempotent.
	if err := f.db.RecordObservedAssetEdges(host, "exec-43"); err != nil {
		t.Fatal(err)
	}
	if g, _ = f.db.ListAssetGraph(f.eng); len(g.Edges) != 2 {
		t.Fatalf("duplicate edges: %+v", g.Edges)
	}
}

func TestListAssetGraphOnlyEngagementAssets(t *testing.T) {
	f := newRelFixture(t)
	other, _ := f.db.CreateEngagement(&Engagement{Name: "Other"})
	a, b := f.asset(t, f.eng, "a.example.com", "", ""), f.asset(t, f.eng, "b.example.com", "", "")
	x, y := f.asset(t, other.ID, "x.other.test", "", ""), f.asset(t, other.ID, "y.other.test", "", "")
	f.asset(t, "", "loose.test", "", "")
	for _, p := range [][3]string{{f.eng, a, b}, {other.ID, x, y}} {
		if _, err := f.db.UpsertAssetRelationship(AssetRelationshipInput{EngagementID: p[0], FromAssetID: p[1], ToAssetID: p[2],
			RelationType: RelConnectsTo, Confidence: ConfInferred}); err != nil {
			t.Fatal(err)
		}
	}
	// A stray edge pointing at a foreign asset must not leak.
	if _, err := f.db.Exec(`INSERT INTO asset_relationships (id,engagement_id,from_asset_id,to_asset_id,relation_type,confidence,created_at) VALUES ('stray',?,?,?,'CONNECTS_TO','inferred',CURRENT_TIMESTAMP)`, f.eng, a, x); err != nil {
		t.Fatal(err)
	}
	g, err := f.db.ListAssetGraph(f.eng)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 || g.Edges[0].FromAssetID != a || g.Edges[0].ToAssetID != b {
		t.Fatalf("graph = %+v", g)
	}
}
