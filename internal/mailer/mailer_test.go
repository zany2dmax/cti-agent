package mailer

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- the gate

// The most security-relevant decision in the codebase, so it gets a truth
// table rather than a couple of examples. In Python this logic could only be
// exercised by sending mail, which is why it never was.
func TestTheAllowlistGate(t *testing.T) {
	const (
		dl   = "cyber@example.com"
		op   = "operator@example.com"
		out1 = "stranger@example.com"
	)
	cases := []struct {
		name     string
		to, cc   []string
		allowRaw string
		digestTo string
		operator string
		approved bool
		wantErr  bool
		why      string
	}{
		{"the scheduled digest", []string{dl}, nil, dl, dl, op, false, false,
			"the standing recipient is pre-approved"},
		{"an escalation to the operator", []string{op}, nil, dl, dl, op, false, false,
			"the orchestrator must be able to ask a question without permission to ask"},
		{"a stranger on To", []string{out1}, nil, dl, dl, op, false, true,
			"nobody approved this address"},

		// The one that matters most: a header name must not defeat the gate.
		{"a stranger on Cc", []string{dl}, []string{out1}, dl, dl, op, false, true,
			"exempting Cc would make the allowlist trivially bypassable"},
		{"a stranger on Cc, approved", []string{dl}, []string{out1}, dl, dl, op, true, false,
			"an explicit human OK on this specific send"},

		// Fail closed when unconfigured: the allowlist falls back to DIGEST_TO,
		// not to everything.
		{"no allowlist set, digest recipient", []string{dl}, nil, "", dl, op, false, false,
			"FLEET_ALLOW_TO defaults to DIGEST_TO"},
		{"no allowlist set, stranger", []string{out1}, nil, "", dl, op, false, true,
			"the default must not be 'anyone'"},
		{"neither set, any recipient", []string{dl}, nil, "", "", "", false, true,
			"an empty allowlist allows nobody, not everybody"},

		{"case differs", []string{"CYBER@Example.COM"}, nil, dl, dl, op, false, false,
			"addresses are compared case-insensitively"},
		{"whitespace in the allowlist", []string{dl}, nil, " " + dl + " , x@y.zz", dl, op,
			false, false, "a hand-edited list has spaces in it"},
		{"operator empty, operator addressed", []string{op}, nil, dl, dl, "", false, true,
			"with no operator configured there is no pre-approval to inherit"},
	}
	for _, c := range cases {
		err := CheckAllowed(c.to, c.cc, c.allowRaw, c.digestTo, c.operator, c.approved)
		if c.wantErr && err == nil {
			t.Errorf("%s: allowed the send, want refusal (%s)", c.name, c.why)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: refused the send: %v (%s)", c.name, err, c.why)
		}
	}
}

// The refusal has to name the addresses. An operator seeing "recipients
// outside FLEET_ALLOW_TO" with no names cannot tell a typo from an intruder.
func TestTheRefusalNamesEveryAddressItRefused(t *testing.T) {
	err := CheckAllowed(
		[]string{"a@x.com", "b@x.com"}, []string{"c@x.com"},
		"a@x.com", "", "", false)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"b@x.com", "c@x.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "a@x.com") {
		t.Error("the allowed address should not be listed as outside")
	}
	if !strings.Contains(err.Error(), "--approve") {
		t.Error("the refusal should say how to proceed deliberately")
	}
}

// ------------------------------------------------------------- the audience

func TestResolveDerivesToAndCc(t *testing.T) {
	cases := []struct {
		name   string
		a      Audience
		wantTo []string
		wantCC []string
		errish string
	}{
		{"digest defaults",
			Audience{DigestTo: "dl@x.com", DigestCC: "a@x.com,b@x.com"},
			[]string{"dl@x.com"}, []string{"a@x.com", "b@x.com"}, ""},

		{"--to overrides DIGEST_TO",
			Audience{ToFlag: "other@x.com", DigestTo: "dl@x.com"},
			[]string{"other@x.com"}, nil, ""},

		{"escalation goes to the operator and is never Cc'd",
			Audience{ToOperator: true, Operator: "op@x.com", DigestCC: "a@x.com"},
			[]string{"op@x.com"}, nil, ""},

		{"Cc that duplicates To is dropped",
			Audience{DigestTo: "dl@x.com", CCFlag: "dl@x.com,a@x.com"},
			[]string{"dl@x.com"}, []string{"a@x.com"}, ""},

		{"Cc duplicate differing in case is still dropped",
			Audience{DigestTo: "dl@x.com", CCFlag: "DL@X.com"},
			[]string{"dl@x.com"}, nil, ""},

		{"Cc from the allowlist when opted in",
			Audience{DigestTo: "dl@x.com", CCFromAllow: true,
				AllowRaw: "dl@x.com,a@x.com", Operator: "op@x.com"},
			[]string{"dl@x.com"}, []string{"a@x.com"},
			""},

		{"whitespace and empty entries survive nothing",
			Audience{DigestTo: " dl@x.com , , a@x.com "},
			[]string{"dl@x.com", "a@x.com"}, nil, ""},

		{"no recipients at all", Audience{}, nil, nil, "no recipients"},
		{"--to-operator with --to", Audience{ToOperator: true, ToFlag: "x@y.zz",
			Operator: "op@x.com"}, nil, nil, "mutually exclusive"},
		{"--to-operator with no operator", Audience{ToOperator: true}, nil, nil,
			"FLEET_OPERATOR_EMAIL"},
		{"a malformed address", Audience{DigestTo: "not-an-address"}, nil, nil,
			"not a valid address"},
	}
	for _, c := range cases {
		to, cc, err := c.a.Resolve()
		if c.errish != "" {
			if err == nil || !strings.Contains(err.Error(), c.errish) {
				t.Errorf("%s: err = %v, want one mentioning %q", c.name, err, c.errish)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if strings.Join(to, ",") != strings.Join(c.wantTo, ",") {
			t.Errorf("%s: to = %v, want %v", c.name, to, c.wantTo)
		}
		if strings.Join(cc, ",") != strings.Join(c.wantCC, ",") {
			t.Errorf("%s: cc = %v, want %v", c.name, cc, c.wantCC)
		}
	}
}

// The Cc-from-allowlist option reads the RAW allowlist, not the one the gate
// augments with the operator. Otherwise enabling it would silently subscribe
// the operator to every digest - which is not what it asks for.
func TestCcFromAllowlistDoesNotSubscribeTheOperator(t *testing.T) {
	_, cc, err := Audience{
		DigestTo:    "dl@x.com",
		CCFromAllow: true,
		AllowRaw:    "dl@x.com,a@x.com",
		Operator:    "op@x.com",
	}.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, r := range cc {
		if strings.EqualFold(r, "op@x.com") {
			t.Error("the operator was CC'd on a digest by enabling " +
				"DIGEST_CC_FROM_ALLOW_TO; list them in FLEET_ALLOW_TO " +
				"explicitly if that is wanted")
		}
	}
}

// ----------------------------------------------------------------- subjects

func TestSubject(t *testing.T) {
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name, raw, board string
		msg              bool
		want             string
	}{
		{"explicit", "Hello", "", false, "Hello"},
		{"default when empty", "", "", false, "CTI Brief 2026-09-30"},
		{"default when blank", "   ", "", false, "CTI Brief 2026-09-30"},
		{"board id prefixed in message mode", "Approve?", "q17", true,
			"[FLEET q17] Approve?"},
		{"board id not duplicated", "[FLEET q17] Approve?", "q17", true,
			"[FLEET q17] Approve?"},
		{"board id ignored for a digest", "Digest", "q17", false, "Digest"},
		// A newline in a mail header is a header-injection primitive as well
		// as a rendering bug.
		{"newlines collapsed", "one\ntwo\r\nthree", "", false, "one two three"},
		{"runs of spaces collapsed", "a    b", "", false, "a b"},
	}
	for _, c := range cases {
		if got := Subject(c.raw, c.board, c.msg, now); got != c.want {
			t.Errorf("%s: Subject = %q, want %q", c.name, got, c.want)
		}
	}
	long := Subject(strings.Repeat("x", 400), "", false, now)
	if len(long) != MaxSubject {
		t.Errorf("a long subject is %d chars, want %d", len(long), MaxSubject)
	}
}

func TestOnlySev5EarnsHighImportance(t *testing.T) {
	if !HighImportance("[Sev5] CTI Sep 30: 3 exploited vulns present") {
		t.Error("a Sev5 subject should be flagged urgent")
	}
	for _, s := range []string{
		"[Sev4] CTI Sep 30", "CTI Sep 30", "Re: [Sev5] forwarded",
		"URGENT", "[sev5] lowercase",
	} {
		if HighImportance(s) {
			t.Errorf("%q should not be urgent - a system that marks everything "+
				"urgent has marked nothing urgent", s)
		}
	}
}

// ------------------------------------------------------------ misc helpers

func TestTruthyIsStrictAboutWhatEnablesAControl(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE", "True", "yes", "on", " yes "} {
		if !Truthy(s) {
			t.Errorf("Truthy(%q) = false; fleet.env is hand-edited", s)
		}
	}
	// Anything unrecognised is false. A flag that turns a security control
	// into a distribution list must not be enabled by a typo.
	for _, s := range []string{"", "no", "false", "0", "off", "y", "ture", "enabled"} {
		if Truthy(s) {
			t.Errorf("Truthy(%q) = true; unrecognised values must be false", s)
		}
	}
}

func TestValidAddress(t *testing.T) {
	for _, s := range []string{"a@b.co", "first.last@sub.example.com", "x+tag@y.io"} {
		if !ValidAddress(s) {
			t.Errorf("ValidAddress(%q) = false", s)
		}
	}
	for _, s := range []string{"", "no-at-sign", "a@b", "a b@c.com", "a@b c.com", "@b.com"} {
		if ValidAddress(s) {
			t.Errorf("ValidAddress(%q) = true", s)
		}
	}
}

// The escalation body carries operator-supplied text, and the fleet's own
// board ids, into HTML.
func TestEscalationHTMLEscapesItsInputs(t *testing.T) {
	body := EscalationHTML("<script>alert(1)</script>\n\nsecond para",
		"q<17", "reply@x.com")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("message text reached the body unescaped")
	}
	if strings.Contains(body, "[FLEET q<17]") {
		t.Error("the board id reached the body unescaped")
	}
	if !strings.Contains(body, "reply@x.com") {
		t.Error("the reply address should be shown - an escalation nobody " +
			"knows how to answer stalls the fleet")
	}
	if n := strings.Count(body, "<p style="); n != 2 {
		t.Errorf("blank-line-separated blocks should become %d paragraphs, got %d", 2, n)
	}
	// A single newline inside a block becomes a break, but only after escaping.
	if !strings.Contains(EscalationHTML("a\nb", "", "x@y.zz"), "a<br>b") {
		t.Error("newlines within a block should become <br>")
	}
}
