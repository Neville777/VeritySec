package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedDir(t *testing.T) {
	tmp := t.TempDir()
	work := filepath.Join(tmp, "work")
	root := filepath.Join(tmp, "conversations")
	conv := filepath.Join(root, "c1")
	outside := filepath.Join(tmp, "outside")
	file := filepath.Join(root, "file.txt")
	for _, d := range []string{work, conv, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(file, []byte("x"), 0o600)
	link := filepath.Join(root, "link")
	_ = os.Symlink(outside, link)
	comma := filepath.Join(root, "a,b")
	_ = os.MkdirAll(comma, 0o700)

	cases := []struct {
		name      string
		dir, root string
		wantErr   bool
	}{
		{"valid", conv, root, false},
		{"empty root", conv, "", true},
		{"relative", "conversations/c1", root, true},
		{"missing", filepath.Join(root, "nope"), root, true},
		{"not a dir", file, root, true},
		{"dotdot", root + "/c1/../c1", root, true},
		{"outside root", outside, root, true},
		{"root itself", root, root, true},
		{"symlink escape", link, root, true},
		{"comma", comma, root, true},
		{"colon", conv + ":x", root, true},
		{"nul", conv + "\x00", root, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args, err := BuildRunArgs(Options{
				Image: "img", Network: "none", Memory: "512m", PidsLimit: 64,
				WorkDir: work, Argv: []string{"nuclei"},
				SharedDir: c.dir, SharedRoot: c.root,
			})
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected refusal, got %v", args)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			j := strings.Join(args, " ")
			if !strings.Contains(j, "--volume "+conv+":"+conv+":rw") || !strings.Contains(j, "--workdir "+conv) ||
				!strings.Contains(j, work+":/work:rw") {
				t.Fatalf("unexpected args: %s", j)
			}
		})
	}
}
