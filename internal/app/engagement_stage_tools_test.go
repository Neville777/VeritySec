package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"veritysec/internal/database"
	"veritysec/internal/mcp"

	"go.uber.org/zap"
)

func TestEngagementStageToolRegisteredAndEnforcesRules(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "t.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e, _ := db.CreateEngagement(&database.Engagement{Name: "e"})
	server := mcp.NewServer(zap.NewNop())
	registerEngagementStageTools(server, db, nil)
	found := false
	for _, tl := range server.GetAllTools() {
		found = found || tl.Name == EngagementStageToolName
	}
	if !found {
		t.Fatal("engagement_stage not registered")
	}
	call := func(args map[string]interface{}) (string, bool) {
		res, _, err := server.CallTool(context.Background(), EngagementStageToolName, args)
		if err != nil {
			t.Fatal(err)
		}
		return res.Content[0].Text, res.IsError
	}
	if out, isErr := call(map[string]interface{}{"engagement_id": e.ID, "stage": "ENUMERATION", "action": "start"}); !isErr || !strings.Contains(out, "AUTHORISATION") {
		t.Fatalf("out-of-order start allowed: %s", out)
	}
	if out, isErr := call(map[string]interface{}{"engagement_id": e.ID, "stage": "AUTHORISATION", "action": "skip", "reason": "pre-approved"}); isErr || !strings.Contains(out, "skipped") {
		t.Fatalf("skip: %s", out)
	}
	st, _ := db.ListAssessmentStages(e.ID)
	if st[0].InitiatedBy != "agent" {
		t.Fatalf("actor = %q", st[0].InitiatedBy)
	}
}

func TestEngagementStageToolIsAlwaysVisibleInConfig(t *testing.T) {
	b, err := readFileForTest("../../config.yaml")
	if err != nil || !strings.Contains(string(b), "\n    - engagement_stage\n") {
		t.Fatalf("config.yaml lacks engagement_stage: %v", err)
	}
}

func readFileForTest(p string) ([]byte, error) { return os.ReadFile(p) }

func TestEngagementStageToolAddTask(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "t.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e, _ := db.CreateEngagement(&database.Engagement{Name: "e"})
	server := mcp.NewServer(zap.NewNop())
	registerEngagementStageTools(server, db, nil)
	call := func(args map[string]interface{}) (string, bool) {
		res, _, err := server.CallTool(context.Background(), EngagementStageToolName, args)
		if err != nil {
			t.Fatal(err)
		}
		return res.Content[0].Text, res.IsError
	}
	if out, isErr := call(map[string]interface{}{"engagement_id": e.ID, "stage": "RECONNAISSANCE", "action": "add_task", "title": "Check new subdomain"}); isErr || !strings.Contains(out, "Check new subdomain") {
		t.Fatalf("add_task: %s", out)
	}
	tasks, _ := db.ListStageTasks(e.ID, "RECONNAISSANCE")
	if len(tasks) != 1 || tasks[0].ProposedBy != database.StageTaskByModel || !tasks[0].Required {
		t.Fatalf("tasks: %+v", tasks)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, "AUTHORISATION", database.StageTransition{Action: "skip", Reason: "x", Actor: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, isErr := call(map[string]interface{}{"engagement_id": e.ID, "stage": "AUTHORISATION", "action": "add_task", "title": "late"}); !isErr {
		t.Fatal("add_task to a skipped stage must be refused")
	}
}
