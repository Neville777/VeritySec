package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "sbx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if home, err := os.UserHomeDir(); err == nil && (d == home || strings.HasPrefix(d, home+"/")) {
		t.Skip("temp dir is under home; cannot test valid case")
	}
	return d
}

func TestBuildRunArgsValid(t *testing.T) {
	d := tempDir(t)
	got, err := BuildRunArgs(Options{
		Image: "kalilinux/kali:latest", Network: "host",
		CapAdd: []string{"NET_RAW", "NET_ADMIN"}, Memory: "512m", PidsLimit: 128,
		WorkDir: d, Argv: []string{"nmap", "-sV", "a b; $(x)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"run", "--rm", "--read-only", "--tmpfs", "/tmp", "--env", "HOME=/tmp",
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL",
		"--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
		"--memory", "512m", "--pids-limit", "128", "--network", "host",
		"--volume", d + ":/work:rw", "--workdir", "/work",
		"kalilinux/kali:latest", "nmap", "-sV", "a b; $(x)"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	for _, a := range got {
		if strings.Contains(a, "--privileged") || strings.Contains(a, "/var/run/docker.sock") {
			t.Fatalf("forbidden element %q", a)
		}
	}
	n := 0
	for _, a := range got {
		if a == "--volume" || a == "-v" || a == "--mount" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one mount, got %d", n)
	}
}

func TestBuildRunArgsRefusals(t *testing.T) {
	d := tempDir(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	valid := func() Options {
		return Options{Image: "img:1", Network: "none", Memory: "64m", PidsLimit: 10,
			WorkDir: d, Argv: []string{"ls"}}
	}
	cases := []struct {
		name string
		mut  func(*Options)
	}{
		{"empty image", func(o *Options) { o.Image = "" }},
		{"image whitespace", func(o *Options) { o.Image = "a b" }},
		{"image tab", func(o *Options) { o.Image = "a\tb" }},
		{"image dash", func(o *Options) { o.Image = "--privileged" }},
		{"network bridge", func(o *Options) { o.Network = "bridge" }},
		{"network empty", func(o *Options) { o.Network = "" }},
		{"memory bad unit", func(o *Options) { o.Memory = "10x" }},
		{"memory empty", func(o *Options) { o.Memory = "" }},
		{"memory uppercase", func(o *Options) { o.Memory = "10M" }},
		{"memory newline", func(o *Options) { o.Memory = "10m\n" }},
		{"pids zero", func(o *Options) { o.PidsLimit = 0 }},
		{"pids too high", func(o *Options) { o.PidsLimit = 4097 }},
		{"workdir relative", func(o *Options) { o.WorkDir = "relative/dir" }},
		{"workdir missing", func(o *Options) { o.WorkDir = d + "/nope" }},
		{"workdir is file", func(o *Options) { o.WorkDir = "/etc/hostname" }},
		{"workdir home", func(o *Options) { o.WorkDir = home }},
		{"workdir root", func(o *Options) { o.WorkDir = "/" }},
		{"workdir etc", func(o *Options) { o.WorkDir = "/etc" }},
		{"workdir under etc", func(o *Options) { o.WorkDir = "/etc/ssl" }},
		{"workdir var", func(o *Options) { o.WorkDir = "/var" }},
		{"workdir var/run", func(o *Options) { o.WorkDir = "/var/run" }},
		{"workdir proc", func(o *Options) { o.WorkDir = "/proc" }},
		{"workdir sys", func(o *Options) { o.WorkDir = "/sys" }},
		{"workdir dev", func(o *Options) { o.WorkDir = "/dev" }},
		{"argv empty", func(o *Options) { o.Argv = nil }},
		{"argv0 slash", func(o *Options) { o.Argv = []string{"/bin/ls"} }},
		{"argv0 space", func(o *Options) { o.Argv = []string{"ls -l"} }},
		{"argv0 newline", func(o *Options) { o.Argv = []string{"ls\n"} }},
		{"argv0 empty", func(o *Options) { o.Argv = []string{""} }},
		{"argv0 nul", func(o *Options) { o.Argv = []string{"l\x00s"} }},
		{"argv nul later", func(o *Options) { o.Argv = []string{"ls", "a\x00b"} }},
		{"cap lowercase", func(o *Options) { o.CapAdd = []string{"net_raw"} }},
		{"cap injection", func(o *Options) { o.CapAdd = []string{"ALL,x"} }},
		{"cap nul", func(o *Options) { o.CapAdd = []string{"NET\x00"} }},
	}
	for _, m := range strings.Split(";|&$`<>(){}*?'\"\\", "") {
		m := m
		cases = append(cases, struct {
			name string
			mut  func(*Options)
		}{"argv0 meta " + m, func(o *Options) { o.Argv = []string{"a" + m + "b"} }})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := valid()
			c.mut(&o)
			if got, err := BuildRunArgs(o); err == nil {
				t.Fatalf("expected error, got %q", got)
			}
		})
	}
}

// TestWorkDirHomeRules uses a fake HOME so nothing in the real home is touched.
func TestWorkDirHomeRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mk := func(rel string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	try := func(w string) error {
		_, err := BuildRunArgs(Options{Image: "img:1", Network: "none", Memory: "64m", PidsLimit: 10,
			WorkDir: w, Argv: []string{"ls"}})
		return err
	}
	if err := try(mk("data/sandbox-runs/abc")); err != nil {
		t.Errorf("path under home should be accepted: %v", err)
	}
	if err := try(mk("apps")); err != nil {
		t.Errorf("path under home should be accepted: %v", err)
	}
	for _, rel := range []string{"", ".ssh", ".docker", ".docker/sub", ".gnupg", ".aws", ".config/x", ".kube", ".claude", ".cache/y"} {
		w := home
		if rel != "" {
			w = mk(rel)
		}
		if err := try(w); err == nil {
			t.Errorf("%q should be refused", rel)
		}
	}
}
