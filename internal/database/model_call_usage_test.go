package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestModelCallUsageManifestColumnIsAddedOnceToOldTable(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "u.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE model_call_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL, call_index INTEGER NOT NULL,
		prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0, cached_tokens INTEGER NOT NULL DEFAULT 0, total_tokens INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := db.ensureModelCallUsageManifestColumn(); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('model_call_usage') WHERE name='manifest_json'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("manifest_json columns = %d, err %v", n, err)
	}
}
