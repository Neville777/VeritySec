package database

import (
	"strings"
	"sync"
	"testing"
)

func TestRunEventsSeqGapFreeUnderConcurrency(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	const workers, per = 8, 15
	var wg sync.WaitGroup
	errs := make(chan error, workers*per)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if _, err := db.AppendRunEvent(assistant.ID, conv.ID, "", "progress", "", map[string]interface{}{"i": i}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	evs, err := db.ListRunEvents(assistant.ID, 0, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != workers*per {
		t.Fatalf("got %d events, want %d", len(evs), workers*per)
	}
	for i, e := range evs {
		if e.Seq != int64(i+1) {
			t.Fatalf("event %d has seq %d, want %d (gap or reorder)", i, e.Seq, i+1)
		}
	}
}

func TestRunEventsNeverStoreToolOutput(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	big := strings.Repeat("SECRETOUTPUT", 5000)
	data := map[string]interface{}{
		"toolName": "nmap", "executionId": "exec-1", "success": true,
		"result": big, "output": big, "stdout": big, "resultPreview": big,
		"extra": map[string]interface{}{"stderr": big, "note": big},
	}
	_, seq, err := db.AddProcessDetailWithRunSeq(assistant.ID, conv.ID, "tool_result", "tool output: "+big, data)
	if err != nil || seq != 1 {
		t.Fatalf("seq=%d err=%v", seq, err)
	}
	evs, err := db.ListRunEvents(assistant.ID, 0, 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events=%v err=%v", evs, err)
	}
	raw := string(evs[0].Data)
	if strings.Contains(raw, big[:1000]) || len(raw) > 1500 || strings.Contains(raw, `"stdout"`) || strings.Contains(raw, `"stderr"`) || strings.Contains(raw, `"result"`) || strings.Contains(raw, `"output"`) {
		t.Fatalf("data_json holds tool output (len %d)", len(raw))
	}
	if !strings.Contains(raw, "nmap") || !strings.Contains(raw, "exec-1") {
		t.Fatalf("identifiers missing: %s", raw)
	}
	if evs[0].EventType != "tool_result" {
		t.Fatalf("type %q", evs[0].EventType)
	}
}

func TestRunEventsReplayAfterSeqAndCheckpointMirror(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	for i := 0; i < 5; i++ {
		if err := db.AddProcessDetail(assistant.ID, conv.ID, "progress", "step", nil); err != nil {
			t.Fatal(err)
		}
	}
	// Checkpoint without a message ID falls back to the latest message (best-effort).
	if err := db.WriteRunCheckpoint("", conv.ID, "", "RECON", CheckpointKindStageStart, map[string]interface{}{"stage": "RECON"}); err != nil {
		t.Fatal(err)
	}
	evs, err := db.ListRunEvents(assistant.ID, 3, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 || evs[0].Seq != 4 || evs[2].Seq != 6 || evs[2].EventType != CheckpointKindStageStart {
		t.Fatalf("unexpected replay: %+v", evs)
	}
	if evs, _ = db.ListRunEvents(assistant.ID, 6, 500); len(evs) != 0 {
		t.Fatalf("expected none, got %d", len(evs))
	}
}
