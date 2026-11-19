package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The verdict is read from the trace's LAST result event, as fleet-trace
// writes it: earlier lines (tool output, other JSON) are not the answer.
func TestTheFinalMessageIsTheTracesResultEvent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "checkin.jsonl")
	body := `{"type":"fleet_trace","version":1,"unit":"checkin"}
{"type":"user","message":{"content":[{"type":"tool_result","content":"{\"schema\":\"cti-checkin/1\"}"}]}}
{"type":"result","result":"first"}
not json at all
{"type":"result","result":"the real answer"}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := finalMessage(p, "")
	if err != nil || got != "the real answer" {
		t.Errorf("got %q, %v", got, err)
	}
	if got, _ := finalMessage(filepath.Join(t.TempDir(), "none"), ""); got != "" {
		t.Errorf("a missing trace gave %q", got)
	}
}
