package jira

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tr(id, name, to, cat string, fields map[string]TransitionField) Transition {
	t := Transition{ID: id, Name: name, Fields: fields}
	t.To.Name = to
	t.To.StatusCategory.Key = cat
	return t
}

func TestChooseCloseByStatusCategoryNotName(t *testing.T) {
	ts := []Transition{
		tr("1", "Start", "In Progress", "indeterminate", nil),
		tr("2", "Close it", "Finished", "done", nil), // renamed workflow: category still says done
	}
	ch, err := ChooseClose(ts, "")
	if err != nil || ch.Transition.ID != "2" || ch.Resolution != "" {
		t.Fatalf("got %+v, %v", ch, err)
	}
}

func TestChooseCloseNothingDone(t *testing.T) {
	if _, err := ChooseClose([]Transition{tr("1", "Start", "In Progress", "indeterminate", nil)}, ""); err == nil {
		t.Fatal("no done transition must be an error")
	}
}

func TestChooseCloseAmbiguousNeedsPreference(t *testing.T) {
	ts := []Transition{
		tr("2", "Done", "Done", "done", nil),
		tr("3", "Won't Do", "Won't Do", "done", nil),
	}
	if _, err := ChooseClose(ts, ""); err == nil || !strings.Contains(err.Error(), "JIRA_CLOSE_TRANSITION") {
		t.Fatalf("ambiguity must name the setting, got %v", err)
	}
	if _, err := ChooseClose(ts, "no such"); err == nil {
		t.Fatal("a preference matching nothing must not fall back to a guess")
	}
	ch, err := ChooseClose(ts, " done ")
	if err != nil || ch.Transition.ID != "2" {
		t.Fatalf("preferred transition not used: %+v, %v", ch, err)
	}
}

func TestChooseCloseHonoursAPreferenceEvenWithOneCandidate(t *testing.T) {
	only := []Transition{tr("3", "Won't Do", "Won't Do", "done", nil)}
	if _, err := ChooseClose(only, "Done"); err == nil {
		t.Fatal("a lone Won't Do must not be used when Done was asked for")
	}
	if ch, err := ChooseClose(only, ""); err != nil || ch.Transition.ID != "3" {
		t.Fatalf("no preference: the one candidate is used: %+v, %v", ch, err)
	}
}

func TestChooseCloseResolutionAndBlockers(t *testing.T) {
	withRes := tr("2", "Done", "Done", "done", map[string]TransitionField{
		"resolution": {Required: true},
		"comment":    {Required: false},
	})
	ch, err := ChooseClose([]Transition{withRes}, "")
	if err != nil || ch.Resolution != ResolutionName {
		t.Fatalf("resolution not set: %+v, %v", ch, err)
	}
	blocked := tr("2", "Done", "Done", "done", map[string]TransitionField{
		"customfield_10050": {Required: true},
	})
	if _, err := ChooseClose([]Transition{blocked}, ""); err == nil ||
		!strings.Contains(err.Error(), "customfield_10050") {
		t.Fatalf("an unfillable required field must refuse, got %v", err)
	}
	defaulted := tr("2", "Done", "Done", "done", map[string]TransitionField{
		"customfield_10050": {Required: true, HasDefaultValue: true},
	})
	if _, err := ChooseClose([]Transition{defaulted}, ""); err != nil {
		t.Fatalf("a required field with a default is fine: %v", err)
	}
}

func TestCheckCloseAllowed(t *testing.T) {
	if CheckCloseAllowed("CR", "") == nil {
		t.Error("empty list must refuse")
	}
	if CheckCloseAllowed("CR", "OPS, cr") != nil {
		t.Error("listed project (any case) must pass")
	}
	if CheckCloseAllowed("CR", "OPS") == nil {
		t.Error("unlisted project must refuse")
	}
	if CheckCloseAllowed("", "CR") == nil {
		t.Error("no project key must refuse")
	}
	// Creating is not closing.
	if CheckAllowed("CR", "CR") != nil || CheckCloseAllowed("CR", "") == nil {
		t.Error("the two gates must be independent")
	}
}

func TestCloseSendsTransitionCommentAndResolutionTogether(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(srv.URL, "a@example.com", "tok")
	ch := CloseChoice{Transition: tr("31", "Done", "Done", "done", nil), Resolution: "Done"}
	if err := c.Close(context.Background(), "CR-1", ch, "why"); err != nil {
		t.Fatal(err)
	}
	if path != "POST /rest/api/2/issue/CR-1/transitions" {
		t.Errorf("path = %s", path)
	}
	if got["transition"].(map[string]any)["id"] != "31" {
		t.Errorf("transition id missing: %v", got)
	}
	cm := got["update"].(map[string]any)["comment"].([]any)[0].(map[string]any)["add"].(map[string]any)
	if cm["body"] != "why" {
		t.Errorf("comment must travel in the same request: %v", got)
	}
	if got["fields"].(map[string]any)["resolution"].(map[string]any)["name"] != "Done" {
		t.Errorf("resolution missing: %v", got)
	}
}

func TestTransitionsReadsScreenFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("expand") != "transitions.fields" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		}
		_, _ = w.Write([]byte(`{"transitions":[{"id":"31","name":"Done","to":{"name":"Done","statusCategory":{"key":"done"}},
			"fields":{"resolution":{"required":true,"hasDefaultValue":false}}}]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "a@example.com", "tok")
	ts, err := c.Transitions(context.Background(), "CR-1")
	if err != nil || len(ts) != 1 || ts[0].To.StatusCategory.Key != "done" || !ts[0].Fields["resolution"].Required {
		t.Fatalf("got %+v, %v", ts, err)
	}
}

func TestChooseStatusFindsTheOneTransitionByDestinationName(t *testing.T) {
	ts := []Transition{
		tr("2", "Open", "Open", "new", nil),
		tr("3", "To Do", "To Do", "indeterminate", nil),
	}
	got, err := ChooseStatus(ts, " to do ")
	if err != nil || got.ID != "3" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := ChooseStatus(ts, "Backlog"); err == nil {
		t.Error("a status nothing leads to must be an error")
	}
	dup := append(ts, tr("9", "Reset", "To Do", "indeterminate", nil))
	if _, err := ChooseStatus(dup, "To Do"); err == nil {
		t.Error("two transitions to one status must not be guessed between")
	}
	need := []Transition{tr("3", "To Do", "To Do", "indeterminate", map[string]TransitionField{"customfield_1": {Required: true}})}
	if _, err := ChooseStatus(need, "To Do"); err == nil {
		t.Error("a transition that needs a field the fleet cannot fill must be refused")
	}
}

func TestMoveToPostsOnlyTheTransitionIDAndNothingElse(t *testing.T) {
	var posted map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"transitions":[{"id":"2","name":"Open","to":{"name":"Open"}},{"id":"3","name":"To Do","to":{"name":"To Do"}}]}`))
			return
		}
		if r.URL.Path != "/rest/api/2/issue/CYBR-1/transitions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &posted)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(srv.URL, "a@example.com", "tok")
	if err := c.MoveTo(context.Background(), "CYBR-1", "To Do"); err != nil {
		t.Fatal(err)
	}
	if len(posted) != 1 || posted["transition"].(map[string]any)["id"] != "3" {
		t.Errorf("posted %v: want only the transition id, no resolution or comment", posted)
	}
}
