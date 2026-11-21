package mailbox

import (
	"testing"
	"time"
)

// "Automatic reply:" in a subject, or an Auto-Submitted header, is the sender's
// to write. From a sender the receiving server did not authenticate it no longer
// gets a message deleted from the shared inbox: a person decides.
func TestAnUnauthenticatedAutoReplyMarkerDeletesNothing(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	old := now.Add(-100 * time.Hour)
	cases := []struct {
		name string
		c    Candidate
		want Action
		why  string
	}{
		{"verified, subject", Candidate{ID: "1", Subject: "Automatic reply: away", Received: old}, ActionDelete, ""},
		{"verified, header", Candidate{ID: "2", Subject: "hello", AutoReply: true, Received: old}, ActionDelete, ""},
		{"unverified, subject", Candidate{ID: "3", Subject: "Automatic reply: away", Received: old, SenderUnverified: true}, ActionLeave, LeaveAutoReplyUnauth},
		{"unverified, header", Candidate{ID: "4", Subject: "hello", AutoReply: true, Received: old, SenderUnverified: true}, ActionLeave, LeaveAutoReplyUnauth},
	}
	for _, tc := range cases {
		d := PlanWith([]Candidate{tc.c}, nil, Options{Now: now, MinAge: 48 * time.Hour})[0]
		if d.Action != tc.want || d.Why != tc.why {
			t.Errorf("%s: %s/%q, want %s/%q (%s)", tc.name, d.Action, d.Why, tc.want, tc.why, d.Reason)
		}
		if tc.want == ActionLeave && !d.Known {
			t.Errorf("%s: a deliberate leave must not count as an unread backlog", tc.name)
		}
	}
}
