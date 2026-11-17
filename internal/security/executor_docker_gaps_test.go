package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"veritysec/internal/config"

	"github.com/cloudwego/eino/adk/filesystem"
)

func TestSandboxPathStyleCommandUsesBaseName(t *testing.T) {
	out := fakeDocker(t)
	e := newSandboxTestExecutor(t, "/usr/bin/nmap", []string{"-sV"}, dockerCfg())
	res, err := e.ExecuteTool(context.Background(), "t1", map[string]interface{}{})
	if err != nil || res.IsError {
		t.Fatalf("unexpected: %v %+v", err, res)
	}
	b, _ := os.ReadFile(out)
	joined := "\n" + string(b)
	if !strings.Contains(joined, "\nnmap\n") || strings.Contains(joined, "/usr/bin/nmap") {
		t.Fatalf("argv0 not reduced to base name: %q", joined)
	}
	if _, _, _, cerr := e.newToolCommand(context.Background(), "/", nil); cerr == nil {
		t.Fatal("expected refusal for unusable command")
	}
}

func TestSandboxDockerPTYRetryAddsT(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.txt")
	script := "#!/bin/sh\necho \"CALL $*\" >> '" + log + "'\n" +
		"case \"$2\" in -t) echo ok; exit 0;; esac\necho 'Inappropriate ioctl for device'; exit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	e := newSandboxTestExecutor(t, "nmap", []string{"-sV"}, dockerCfg())
	if _, err := e.ExecuteTool(context.Background(), "t1", map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 docker calls, got %v", lines)
	}
	if strings.Contains(lines[0], "run -t") || !strings.HasPrefix(lines[1], "CALL run -t --rm ") {
		t.Fatalf("retry argv wrong: %v", lines)
	}
}

func TestExecToolRefusedInDocker(t *testing.T) {
	out := fakeDocker(t)
	marker := filepath.Join(t.TempDir(), "marker")
	e := newSandboxTestExecutor(t, "echo", nil, dockerCfg())
	t.Cleanup(func() { hostExecRefusedInDocker.Store(false) })
	for _, cmd := range []string{"touch " + marker, "touch " + marker + " &"} {
		res, err := e.executeSystemCommand(context.Background(), map[string]interface{}{"command": cmd})
		if err != nil || res == nil || !res.IsError ||
			!strings.Contains(res.Content[0].Text, "not available while container_runtime is docker") {
			t.Fatalf("expected refusal, got %+v %v", res, err)
		}
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatal("command ran on the host")
	}
	if _, serr := os.Stat(out); !os.IsNotExist(serr) {
		t.Fatal("docker was invoked")
	}
	sh := NewEinoStreamingShell()
	if _, serr := sh.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: "touch " + marker}); serr == nil {
		t.Fatal("shell stream should refuse in docker mode")
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatal("stream command ran on the host")
	}
	e.SetToolExecution(config.ToolExecutionConfig{}, t.TempDir())
	if hostExecRefusedInDocker.Load() {
		t.Fatal("flag should reset in none mode")
	}
}

func TestExecToolRunsInNoneMode(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	e := newSandboxTestExecutor(t, "echo", nil, config.ToolExecutionConfig{})
	res, err := e.executeSystemCommand(context.Background(), map[string]interface{}{"command": "touch " + marker})
	if err != nil || res == nil || res.IsError {
		t.Fatalf("unexpected: %+v %v", res, err)
	}
	if _, serr := os.Stat(marker); serr != nil {
		t.Fatal("exec did not run in none mode")
	}
}
