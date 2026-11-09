package supplier

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// EvalCase is one invented request with the answer it should get. The cases are
// shared by the model evaluation (eval_test.go, run by hand with `task
// eval:supplier`) and by the checks below, which run with every `go test` and
// need no model.
type EvalCase struct {
	Name    string   `json:"name"`
	Tags    []string `json:"tags"`
	Subject string   `json:"subject"`
	Sender  string   `json:"sender"`
	Body    string   `json:"body"`
	State   string   `json:"state"`
	Form    *Form    `json:"form"`
	// Want is the verdict the request should get; AlsoOK lists others that are
	// acceptable. Anything else is a miss, and a final No where No is not wanted
	// or acceptable is a DANGEROUS miss: a supplier waved through.
	Want   string   `json:"want"`
	AlsoOK []string `json:"also_ok"`
}

func (c EvalCase) acceptable(v string) bool {
	if v == c.Want {
		return true
	}
	for _, a := range c.AlsoOK {
		if v == a {
			return true
		}
	}
	return false
}

// input is the request as the lane would hand it to the model.
func (c EvalCase) input() Input {
	return Input{
		MessageID: "eval-" + c.Name, Received: "2026-11-05T10:00:00Z",
		Sender: c.Sender, Subject: c.Subject, Body: c.Body,
		State: FormState(c.State), Form: c.Form,
	}
}

func loadEvalCases(t testing.TB) []EvalCase {
	t.Helper()
	b, err := os.ReadFile("testdata/eval/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []EvalCase
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatalf("cases.json: %v", err)
	}
	return cases
}

func TestTheEvalCasesAreSoundAndInventedAndNeverWantAHostileNo(t *testing.T) {
	cases := loadEvalCases(t)
	if len(cases) < 20 {
		t.Errorf("only %d cases", len(cases))
	}
	seen := map[string]bool{}
	tags := map[string]int{}
	for _, c := range cases {
		if c.Name == "" || seen[c.Name] {
			t.Errorf("case name %q is empty or repeated", c.Name)
		}
		seen[c.Name] = true
		switch c.Want {
		case Yes, No, Unsure:
		default:
			t.Errorf("%s: want %q is not yes, no or unsure", c.Name, c.Want)
		}
		for _, a := range c.AlsoOK {
			if a != Yes && a != No && a != Unsure {
				t.Errorf("%s: also_ok %q", c.Name, a)
			}
		}
		switch FormState(c.State) {
		case StateRead:
			if c.Form == nil {
				t.Errorf("%s: state read with no form", c.Name)
			}
		case StateNone, StateLinked, StateUnreadable:
			if c.Form != nil {
				t.Errorf("%s: a form is given but the state is %s", c.Name, c.State)
			}
		default:
			t.Errorf("%s: unknown state %q", c.Name, c.State)
		}
		for _, tg := range c.Tags {
			tags[tg]++
			// A hostile or gated request must never be allowed a No: that is the
			// whole point of these cases.
			if (tg == "hostile" || tg == "technology" || tg == "gate" || tg == "unknown") && c.acceptable(No) && c.Name != "materials_name_tech_word" {
				t.Errorf("%s (%s) allows a No", c.Name, tg)
			}
		}
		// Invented data only: no real-looking domain or address.
		text := strings.ToLower(c.Sender + " " + c.Subject + " " + c.Body)
		if c.Form != nil {
			text += " " + strings.ToLower(c.Form.Name+" "+c.Form.Notes)
		}
		if strings.Contains(c.Sender, "@") && !strings.HasSuffix(c.Sender, "@example.test") {
			t.Errorf("%s: sender %q is not an @example.test address", c.Name, c.Sender)
		}
		for _, bad := range []string{"@gmail", "@outlook", ".com ", "http://", "https://"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s: contains %q: use invented names only", c.Name, bad)
			}
		}
	}
	for _, need := range []string{"materials", "technology", "hostile", "gate", "unknown"} {
		if tags[need] == 0 {
			t.Errorf("no case is tagged %q", need)
		}
	}
}

func TestEveryCaseCanBeRenderedAndItsHostileTextStaysInsideTheBlock(t *testing.T) {
	for _, c := range loadEvalCases(t) {
		out := Render(c.input(), Config{})
		head, rest, ok := strings.Cut(out, beginMark)
		if !ok {
			t.Errorf("%s: no untrusted block", c.Name)
			continue
		}
		// Exactly one block: a case that tries to close it must not succeed.
		if strings.Count(out, endMark) != 1 || strings.Count(out, beginMark) != 1 {
			t.Errorf("%s: the request closed or reopened the block", c.Name)
		}
		if strings.Contains(head, c.Subject) && c.Subject != "" {
			t.Errorf("%s: request text leaked outside the block", c.Name)
		}
		_ = rest
	}
}

func TestTheRunnerSaysEveryFlagTheEvalCallsTheModelWith(t *testing.T) {
	b, err := os.ReadFile("../../fleet-kit/fleet/bin/run-supplier")
	if err != nil {
		t.Fatal(err)
	}
	runner := string(b)
	args := ModelArgs("m", "p")
	for i, a := range args {
		if !strings.HasPrefix(a, "--") {
			continue
		}
		if !strings.Contains(runner, a) {
			t.Errorf("run-supplier does not pass %s, which ModelArgs (and so the eval) does", a)
		}
		if a == "--tools" && args[i+1] != "" {
			t.Errorf("ModelArgs gives the model tools: %q", args[i+1])
		}
	}
	if !strings.Contains(runner, `--tools ""`) {
		t.Error(`run-supplier does not pass --tools "" (no tools)`)
	}
}
