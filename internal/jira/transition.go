package jira

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// CLOSING A TICKET
//
// The fleet changes a ticket's status in exactly one case: the AppSec ticket
// of an application that is no longer defined in the scanner, when the
// operator has put the project in JIRA_ALLOW_CLOSE. Nothing here decides WHEN
// to close; that is the caller's. This file only knows how to do it safely in a
// workflow it does not own:
//
//   - the transition is chosen by its destination STATUS CATEGORY ("done"),
//     never by a name someone can rename, and refused when ambiguous;
//   - a transition that needs a field the fleet cannot fill is refused rather
//     than guessed at;
//   - the explanatory comment goes in the same request as the transition, so a
//     ticket is never left saying "closed" while still open, or closed
//     without saying why.

// Transition is one workflow transition available on an issue right now.
type Transition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	To   struct {
		Name           string `json:"name"`
		StatusCategory struct {
			Key string `json:"key"`
		} `json:"statusCategory"`
	} `json:"to"`
	// Fields are what the transition's screen asks for.
	Fields map[string]TransitionField `json:"fields"`
}

// TransitionField is one field on a transition screen.
type TransitionField struct {
	Required        bool `json:"required"`
	HasDefaultValue bool `json:"hasDefaultValue"`
}

// Transitions lists what the issue can do now, with each transition's screen
// fields. Read-only.
func (c *Client) Transitions(ctx context.Context, key string) ([]Transition, error) {
	var out struct {
		Transitions []Transition `json:"transitions"`
	}
	path := "/rest/api/2/issue/" + url.PathEscape(key) + "/transitions?expand=transitions.fields"
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Transitions, nil
}

// CloseChoice is the transition to use and the resolution to set with it
// (empty when the transition's screen has no resolution field).
type CloseChoice struct {
	Transition Transition
	Resolution string
}

// ResolutionName is the resolution set when the transition's screen asks for
// one. "Done" is Jira's stock name; a project that renamed it will refuse the
// transition and the failure is reported, never worked around.
const ResolutionName = "Done"

// ChooseClose picks the transition that closes an issue.
//
// Candidates are the transitions whose destination is in the done status
// category. One candidate is used. Several are narrowed by prefer (a
// transition name, case-insensitive, JIRA_CLOSE_TRANSITION); if that does not
// leave exactly one the answer is an error naming the options, because
// guessing between "Done" and "Won't Do" is a decision for a person. A
// candidate needing any required field other than resolution and comment, with
// no default, is not usable.
func ChooseClose(ts []Transition, prefer string) (CloseChoice, error) {
	var cands []Transition
	for _, t := range ts {
		if t.To.StatusCategory.Key == "done" {
			cands = append(cands, t)
		}
	}
	if len(cands) == 0 {
		return CloseChoice{}, fmt.Errorf("no transition leads to a done status from the ticket's current status")
	}
	// A configured preference is honoured even when only one transition
	// qualifies: "Done" was asked for, so a lone "Won't Do" is not it.
	if len(cands) > 1 || strings.TrimSpace(prefer) != "" {
		var narrowed []Transition
		for _, t := range cands {
			if prefer != "" && strings.EqualFold(strings.TrimSpace(prefer), t.Name) {
				narrowed = append(narrowed, t)
			}
		}
		if len(narrowed) != 1 {
			names := make([]string, 0, len(cands))
			for _, t := range cands {
				names = append(names, fmt.Sprintf("%q", t.Name))
			}
			sort.Strings(names)
			return CloseChoice{}, fmt.Errorf("%d transition(s) lead to a done status (%s) and none is the "+
				"one JIRA_CLOSE_TRANSITION names; set it to the one to use", len(cands), strings.Join(names, ", "))
		}
		cands = narrowed
	}
	t := cands[0]
	var blockers []string
	res := ""
	for name, f := range t.Fields {
		switch name {
		case "resolution":
			res = ResolutionName
		case "comment":
		default:
			if f.Required && !f.HasDefaultValue {
				blockers = append(blockers, name)
			}
		}
	}
	if len(blockers) > 0 {
		sort.Strings(blockers)
		return CloseChoice{}, fmt.Errorf("transition %q needs field(s) the fleet cannot fill: %s",
			t.Name, strings.Join(blockers, ", "))
	}
	return CloseChoice{Transition: t, Resolution: res}, nil
}

// Close performs the chosen transition with comment as an explanatory comment
// in the same request. Needs the "Transition issues" permission.
func (c *Client) Close(ctx context.Context, key string, ch CloseChoice, comment string) error {
	body := map[string]any{
		"transition": map[string]string{"id": ch.Transition.ID},
		"update": map[string]any{
			"comment": []any{map[string]any{"add": map[string]string{"body": comment}}},
		},
	}
	if ch.Resolution != "" {
		body["fields"] = map[string]any{"resolution": map[string]string{"name": ch.Resolution}}
	}
	return c.do(ctx, http.MethodPost, "/rest/api/2/issue/"+url.PathEscape(key)+"/transitions", body, nil)
}

// CheckCloseAllowed is the gate for closing, the same shape as CheckAllowed
// and a separate list: allowing the fleet to file tickets does not allow it to
// close them.
func CheckCloseAllowed(projectKey, allowRaw string) error {
	want := strings.ToLower(strings.TrimSpace(projectKey))
	if want == "" {
		return fmt.Errorf("no project key - set JIRA_PROJECT_KEY")
	}
	for _, p := range strings.Split(allowRaw, ",") {
		if strings.EqualFold(strings.TrimSpace(p), want) {
			return nil
		}
	}
	return fmt.Errorf("project %q is not in JIRA_ALLOW_CLOSE (%q); "+
		"add it to fleet.env to let the fleet close tickets there", projectKey, allowRaw)
}

// ClosePermissions are needed only when closing is enabled.
var ClosePermissions = []string{"TRANSITION_ISSUES"}
