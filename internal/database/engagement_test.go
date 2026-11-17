package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestEngagementSchemaIsIdempotentAndAddsNullableColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	for i := 0; i < 2; i++ { // second open must be a no-op
		db, err := NewDB(path, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"conversations", "vulnerabilities"} {
			rows, err := db.Query(`SELECT name, "notnull" FROM pragma_table_info('` + table + `') WHERE name = 'engagement_id'`)
			if err != nil {
				t.Fatal(err)
			}
			if !rows.Next() {
				t.Fatalf("%s.engagement_id missing", table)
			}
			var name string
			var notnull int
			rows.Scan(&name, &notnull)
			rows.Close()
			if notnull != 0 {
				t.Fatalf("%s.engagement_id must be nullable", table)
			}
		}
		db.Close()
	}
}

func TestEvidenceStoreVerifiesHash(t *testing.T) {
	s := &EvidenceStore{Root: t.TempDir()}
	rel, sum, size, err := s.Save("eng", "ev", []byte("hello"))
	if err != nil || size != 5 {
		t.Fatal(err, size)
	}
	ev := &Evidence{StoragePath: rel, SHA256: sum}
	if b, err := s.Read(ev); err != nil || string(b) != "hello" {
		t.Fatalf("read: %q %v", b, err)
	}
	ev.SHA256 = "00" + sum[2:]
	if b, err := s.Read(ev); err != ErrEvidenceHashMismatch || b != nil {
		t.Fatalf("mismatch not reported: %q %v", b, err)
	}
	if _, _, _, err := s.Save("eng", "big", make([]byte, MaxEvidenceBytes+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}
