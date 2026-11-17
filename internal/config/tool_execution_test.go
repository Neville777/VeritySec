package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func loadToolExec(t *testing.T, yamlBody string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestToolExecutionDefaults(t *testing.T) {
	cfg, err := loadToolExec(t, "server:\n  port: 8080\n")
	if err != nil {
		t.Fatal(err)
	}
	te := cfg.ToolExecution
	if te.ContainerRuntimeEffective() != "none" || te.DockerImage != "veritysec-tools:latest" ||
		te.Network != "host" || !reflect.DeepEqual(te.CapAdd, []string{"NET_RAW"}) ||
		te.Memory != "1g" || te.PidsLimit != 256 || te.TimeoutSeconds != 900 {
		t.Fatalf("unexpected defaults: %+v", te)
	}
	if (ToolExecutionConfig{}).ContainerRuntimeEffective() != "none" {
		t.Fatal("zero value should be none")
	}
}

func TestToolExecutionValidation(t *testing.T) {
	ok, err := loadToolExec(t, "tool_execution:\n  container_runtime: docker\n  network: none\n  cap_add: []\n")
	if err != nil {
		t.Fatal(err)
	}
	if ok.ToolExecution.ContainerRuntimeEffective() != "docker" || ok.ToolExecution.Network != "none" || len(ok.ToolExecution.CapAdd) != 0 {
		t.Fatalf("unexpected: %+v", ok.ToolExecution)
	}
	bad := map[string]string{
		"runtime": "tool_execution:\n  container_runtime: podman\n",
		"network": "tool_execution:\n  network: bridge\n",
		"pids0":   "tool_execution:\n  pids_limit: 0\n",
		"image":   "tool_execution:\n  docker_image: \"-x\"\n",
		"cap":     "tool_execution:\n  cap_add: [net_raw]\n",
		"memory":  "tool_execution:\n  memory: 1gb\n",
		"timeout": "tool_execution:\n  timeout_seconds: 5\n",
	}
	for name, body := range bad {
		if _, err := loadToolExec(t, body); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
