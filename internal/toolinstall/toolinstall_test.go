package toolinstall

import (
	"strings"
	"testing"
)

func TestSpecCommandsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range specs {
		if seen[s.Command] {
			t.Fatalf("duplicate command in install table: %s", s.Command)
		}
		seen[s.Command] = true
	}
}

func TestCommandForUserLevelInstallers(t *testing.T) {
	argv, err := commandFor(Spec{Command: "arjun", Method: MethodPipx, Package: "arjun"}, "install")
	if err != nil || strings.Join(argv, " ") != "pipx install arjun" {
		t.Fatalf("pipx install: got %v, %v", argv, err)
	}
	argv, err = commandFor(Spec{Command: "wpscan", Method: MethodGem, Package: "wpscan"}, "install")
	if err != nil || strings.Join(argv, " ") != "gem install --user-install wpscan" {
		t.Fatalf("gem install: got %v, %v", argv, err)
	}
}

func TestStartRefusesManualAndUnknown(t *testing.T) {
	if _, err := Start("hydra", "install"); err == nil {
		t.Fatal("manual apt tool must not be installed by the app")
	}
	if _, err := Start("rm", "install"); err == nil {
		t.Fatal("command outside the install table must be refused")
	}
	if _, err := Start("arjun", "bogus"); err == nil {
		t.Fatal("unknown action must be refused")
	}
}

func TestInventoryHasEveryTool(t *testing.T) {
	rows := Inventory()
	if len(rows) != len(specs) {
		t.Fatalf("inventory rows %d, want %d", len(rows), len(specs))
	}
}
