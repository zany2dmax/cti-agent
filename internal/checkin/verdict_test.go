package checkin

import (
	"encoding/json"
	"strings"
	"testing"
)

// good is a valid verdict: every lane once, nothing sent, one memory row.
func good() map[string]any {
	lanes := []map[string]any{}
	for _, l := range Lanes {
		lanes = append(lanes, map[string]any{"lane": l, "state": "ok"})
	}
	return map[string]any{
		"schema": Schema, "status": "ok", "summary": "Quiet beat.", "lanes": lanes,
		"credential_checks": "already_today", "escalations": []any{},
		"board_writes": 0, "db_writes": 1, "deferred": []any{}, "injection_seen": false,
	}
}

func message(v map[string]any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return "Quiet beat at 15:00. Nothing for the operator.\n\n```json\n" + string(b) + "\n```\n"
}

func kinds(r Result) string { return strings.Join(r.Kinds(), ",") }

func TestAValidVerdictPassesAgainstMatchingCounts(t *testing.T) {
	r := Evaluate(message(good()), &Counts{Bash: 9, DBWrite: 1})
	if !r.Valid {
		t.Fatalf("problems: %v", r.Problems)
	}
	if r.Verdict.Status != "ok" || len(r.Verdict.Lanes) != len(Lanes) {
		t.Errorf("verdict %+v", r.Verdict)
	}
}

func TestTheVerdictIsFoundWithoutAFenceAndAfterOtherJSON(t *testing.T) {
	b, _ := json.Marshal(good())
	msg := `Earlier I read {"note": "not it"} and {"schema": "cti-triage/1"}. Here: ` + string(b)
	if r := Evaluate(msg, nil); !r.Valid {
		t.Errorf("problems: %v", r.Problems)
	}
}

func TestNoVerdictIsMissing(t *testing.T) {
	if r := Evaluate("Quiet beat, nothing to report.", nil); kinds(r) != Missing || r.Valid {
		t.Errorf("got %s %v", kinds(r), r.Problems)
	}
}

func TestSchemaRulesAreInvalid(t *testing.T) {
	cases := map[string]func(v map[string]any){
		"unknown field": func(v map[string]any) { v["mood"] = "fine" },
		"bad status":    func(v map[string]any) { v["status"] = "great" },
		"empty summary": func(v map[string]any) { v["summary"] = " " },
		"long summary":  func(v map[string]any) { v["summary"] = strings.Repeat("x", 301) },
		"lane missing":  func(v map[string]any) { v["lanes"] = v["lanes"].([]map[string]any)[1:] },
		"lane twice": func(v map[string]any) {
			v["lanes"] = append(v["lanes"].([]map[string]any), map[string]any{"lane": "digest", "state": "ok"})
		},
		"unknown lane": func(v map[string]any) {
			v["lanes"] = append(v["lanes"].([]map[string]any), map[string]any{"lane": "billing", "state": "ok"})
		},
		"bad lane state":  func(v map[string]any) { v["lanes"].([]map[string]any)[0]["state"] = "fine" },
		"bad checks":      func(v map[string]any) { v["credential_checks"] = "maybe" },
		"no escalations":  func(v map[string]any) { delete(v, "escalations") },
		"no board writes": func(v map[string]any) { delete(v, "board_writes") },
		"no deferred":     func(v map[string]any) { delete(v, "deferred") },
		"no injection":    func(v map[string]any) { delete(v, "injection_seen") },
		"escalated, none": func(v map[string]any) { v["status"] = "escalated" },
		"sent, says ok": func(v map[string]any) {
			v["escalations"] = []any{map[string]any{"subject": "digest", "why": "not sent"}}
		},
		"half an escalation": func(v map[string]any) {
			v["status"] = "escalated"
			v["escalations"] = []any{map[string]any{"subject": "digest", "why": ""}}
		},
		"wrong schema": func(v map[string]any) { v["schema"] = "cti-checkin/2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := good()
			mutate(v)
			r := Evaluate(message(v), nil)
			if r.Valid {
				t.Fatal("accepted")
			}
			want := Invalid
			if name == "wrong schema" {
				want = Missing // a different schema is not this verdict at all
			}
			if kinds(r) != want {
				t.Errorf("kinds %s, want %s: %v", kinds(r), want, r.Problems)
			}
		})
	}
}

// The model's account against the guard's counts: an alert it did not
// mention, or one it claims and never sent, is a MISMATCH.
func TestClaimsTheGuardDidNotSeeAreMismatches(t *testing.T) {
	v := good()
	if r := Evaluate(message(v), &Counts{Alert: 1, DBWrite: 1}); kinds(r) != Mismatch {
		t.Errorf("unreported alert: %s %v", kinds(r), r.Problems)
	}
	v["status"] = "escalated"
	v["escalations"] = []any{map[string]any{"subject": "jira", "why": "401 on --check"}}
	if r := Evaluate(message(v), &Counts{DBWrite: 1}); kinds(r) != Mismatch {
		t.Errorf("claimed alert never sent: %s %v", kinds(r), r.Problems)
	}
	if r := Evaluate(message(v), &Counts{Alert: 1, DBWrite: 1}); !r.Valid {
		t.Errorf("matching escalation: %v", r.Problems)
	}
	if r := Evaluate(message(good()), &Counts{BoardWrite: 2, DBWrite: 1}); kinds(r) != Mismatch {
		t.Errorf("board writes: %s", kinds(r))
	}
	if r := Evaluate(message(good()), &Counts{}); kinds(r) != Mismatch {
		t.Errorf("db writes: %s", kinds(r))
	}
}

func TestWithoutCountsOnlyTheSchemaIsChecked(t *testing.T) {
	if r := Evaluate(message(good()), nil); !r.Valid {
		t.Errorf("problems: %v", r.Problems)
	}
}
