package security

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"veritysec/internal/config"
	"veritysec/internal/mcp"

	"go.uber.org/zap"
)

func newSandboxTestExecutor(t *testing.T, command string, args []string, te config.ToolExecutionConfig) *Executor {
	t.Helper()
	cfg := &config.SecurityConfig{Tools: []config.ToolConfig{{
		Name: "t1", Command: command, Args: args, Enabled: true,
	}}}
	e := NewExecutor(cfg, mcp.NewServer(zap.NewNop()), zap.NewNop())
	e.SetToolExecution(te, t.TempDir())
	t.Cleanup(func() { hostExecRefusedInDocker.Store(false) })
	return e
}

func fakeDocker(t *testing.T) (out string) {
	t.Helper()
	dir := t.TempDir()
	out = filepath.Join(dir, "docker-args.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + out + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return out
}

func dockerCfg() config.ToolExecutionConfig {
	return config.ToolExecutionConfig{
		ContainerRuntime: "docker", DockerImage: "veritysec-tools:latest", Network: "host",
		CapAdd: []string{"NET_RAW"}, Memory: "1g", PidsLimit: 256, TimeoutSeconds: 60,
	}
}

func TestSandboxRuntimeNoneLaunchArgvUnchanged(t *testing.T) {
	orig := commandBuilder
	var gotName string
	var gotArgs []string
	commandBuilder = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName, gotArgs = name, append([]string(nil), args...)
		return exec.CommandContext(ctx, name, args...)
	}
	defer func() { commandBuilder = orig }()

	e := newSandboxTestExecutor(t, "echo", []string{"hello"}, config.ToolExecutionConfig{})
	res, err := e.ExecuteTool(context.Background(), "t1", map[string]interface{}{})
	if err != nil || res.IsError {
		t.Fatalf("unexpected: %v %+v", err, res)
	}
	if gotName != "echo" || strings.Join(gotArgs, " ") != "hello" {
		t.Fatalf("argv changed under runtime none: %q %q", gotName, gotArgs)
	}
	cmd, _, _, err := e.newToolCommand(context.Background(), "echo", []string{"a", "b"})
	if err != nil || strings.Join(cmd.Args, " ") != "echo a b" {
		t.Fatalf("cmd.Args=%v err=%v", cmd.Args, err)
	}
}

func TestSandboxCommandBuilderSeamNotReplaced(t *testing.T) {
	cmd := commandBuilder(context.Background(), "echo", "x")
	if len(cmd.Args) != 2 || cmd.Args[0] != "echo" {
		t.Fatalf("seam default altered: %v", cmd.Args)
	}
}

func TestSandboxDockerRunsViaDocker(t *testing.T) {
	out := fakeDocker(t)
	e := newSandboxTestExecutor(t, "nmap", []string{"-sV"}, dockerCfg())
	res, err := e.ExecuteTool(context.Background(), "t1", map[string]interface{}{})
	if err != nil || res.IsError {
		t.Fatalf("unexpected: %v %+v", err, res)
	}
	b, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatalf("fake docker did not run: %v", rerr)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if lines[0] != "run" {
		t.Fatalf("first arg %q", lines[0])
	}
	joined := "\n" + strings.Join(lines, "\n") + "\n"
	for _, want := range []string{"--read-only", "--cap-drop", "veritysec-tools:latest", "nmap", "-sV"} {
		if !strings.Contains(joined, "\n"+want+"\n") {
			t.Errorf("missing %q in %v", want, lines)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(e.sandboxBaseDir, "sandbox-runs")); len(ents) != 0 {
		t.Errorf("per-run dir not cleaned up")
	}
}

func TestSandboxDockerRefusalDoesNotRun(t *testing.T) {
	out := fakeDocker(t)
	e := newSandboxTestExecutor(t, "bad name", []string{"hi"}, dockerCfg())
	res, err := e.ExecuteTool(context.Background(), "t1", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.IsError || !strings.Contains(res.Content[0].Text, "forbidden") {
		t.Fatalf("expected refusal result, got %+v", res)
	}
	if _, serr := os.Stat(out); !os.IsNotExist(serr) {
		t.Fatalf("fake docker was executed on refusal")
	}
	if _, _, _, cerr := e.newToolCommand(context.Background(), "bad name", nil); cerr == nil {
		t.Fatal("expected error from newToolCommand")
	}
}
