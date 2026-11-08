package mailbox

import (
	"strings"
	"testing"
	"time"
)

// digestHTML mirrors the real digest's layout: heading table, command links,
// a section heading per category, and one tableitem row per held message
// with a nested table of signed action links. Senders and links are invented.
func digestHTML(sections map[string][][2]string, order []string) string {
	var b strings.Builder
	b.WriteString(`<table><tbody><tr><td class="bigheader">End User Digest: 1 New Message </td></tr>
<tr><td class="commands"><a href="https://filter.example.com/digest?cmd=gendigest&amp;sig=aa">Request New End User Digest</a></td></tr>`)
	for _, sec := range order {
		b.WriteString(`<tr><td><table class="digestable"><tbody><tr><td><table><tbody><tr><td class="tableheader">` +
			sec + `  </td></tr></tbody></table></td></tr><tr><td><table><tbody>` +
			`<tr class="tableheaderc"><td class="labeldiv">From</td><td class="labeldiv">Subject</td><td>Action</td></tr>`)
		for i, r := range sections[sec] {
			cls := "tableitem1"
			if i%2 == 1 {
				cls = "tableitem2"
			}
			b.WriteString(`<tr class="` + cls + `"><td style="text-indent:2px">` + r[0] +
				`</td><td style="text-indent:2px"><a href="https://filter.example.com/digest?cmd=view&amp;sig=bb">` + r[1] +
				`</a> </td><td><table><tbody><tr><td><a href="https://filter.example.com/digest?cmd=release&amp;sig=cc">Release</a></td>` +
				`<td><a href="https://filter.example.com/digest?cmd=releasewhitelist&amp;sig=dd">Release and Allow Sender</a></td>` +
				`<td><a href="https://filter.example.com/digest?cmd=msgblocklist&amp;sig=ee">Block Sender</a></td></tr></tbody></table></td></tr>`)
		}
		b.WriteString(`</tbody></table></td></tr></tbody></table></td></tr>`)
	}
	b.WriteString(`<tr><td class="copyright">Powered by a mail filter</td></tr></tbody></table>`)
	return b.String()
}

func TestParseDigestReadsEveryRowAndNoLink(t *testing.T) {
	body := digestHTML(map[string][][2]string{
		"Low Priority Mail - Quarantined": {
			{"vendor@marketing.example", "Ready to see us in action?"},
			{"qualys@qualys.net", "Qualys: Scan Results &amp; more"},
		},
		"Spam": {{"x@spam.example", "You won\x07 a prize"}},
	}, []string{"Low Priority Mail - Quarantined", "Spam"})

	held := ParseDigest(body)
	if len(held) != 3 {
		t.Fatalf("got %d rows: %+v", len(held), held)
	}
	want := []Held{
		{"Low Priority Mail - Quarantined", "vendor@marketing.example", "Ready to see us in action?"},
		{"Low Priority Mail - Quarantined", "qualys@qualys.net", "Qualys: Scan Results & more"},
		{"Spam", "x@spam.example", "You won a prize"},
	}
	for i := range want {
		if held[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, held[i], want[i])
		}
	}
	for _, h := range held {
		for _, s := range []string{h.Section, h.From, h.Subject} {
			if strings.Contains(s, "http") || strings.Contains(s, "Release") {
				t.Errorf("a link or action leaked into the parsed text: %q - the fleet must never be able to follow one", s)
			}
		}
	}
}

func TestOnlySendersTheFleetReadsCount(t *testing.T) {
	feed := []string{"intel@feeds.example", "@cisa.example"}
	for addr, want := range map[string]bool{
		"qualys@qualys.net":                  true,
		"noreply@mail.qualys.com":            true,
		"Qualys <qualys@qualys.net>":         true,
		"qualys@qualys.net.attacker.example": false,
		"INTEL@feeds.example":                true,
		"other@feeds.example":                false,
		"alerts@cisa.example":                true,
		"alerts@messages.cisa.example":       false, // @domain is that domain exactly
		"vendor@marketing.example":           false,
		"not-an-address":                     false,
	} {
		if got := FleetSender(addr, feed); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	held := []Held{{From: "vendor@marketing.example", Subject: "promo"},
		{From: "qualys@qualys.net", Subject: "Qualys: Scan Results"},
		{From: "alerts@cisa.example", Subject: "Advisory"}}
	if got := HeldForFleet(held, feed); got != "qualys@qualys.net - Qualys: Scan Results; alerts@cisa.example - Advisory" {
		t.Errorf("HeldForFleet = %q", got)
	}
}

func TestADigestHoldingFleetMailStaysForTheOperator(t *testing.T) {
	now := at(9)
	cands := []Candidate{
		{ID: "held", Received: now.Add(-time.Hour), QuarantineDigest: true, DigestRows: 2,
			HeldForFleet: "qualys@qualys.net - Qualys: Scan Results"},
		{ID: "heldold", Received: now.Add(-DigestKeep - time.Hour), QuarantineDigest: true, DigestRows: 1,
			HeldForFleet: "qualys@qualys.net - Qualys: Scan Results"},
		{ID: "noise", Received: now.Add(-time.Hour), QuarantineDigest: true, DigestRows: 1},
		{ID: "unread", Received: now.Add(-time.Hour), QuarantineDigest: true},
	}
	d := map[string]Decision{}
	for _, x := range PlanWith(cands, map[string]Processed{}, Options{Now: now, MinAge: 48 * time.Hour,
		HoldArchive: "the digest has read no mail today"}) {
		d[x.ID] = x
	}
	if d["held"].Action != ActionLeave || !strings.Contains(d["held"].Reason, "release it") ||
		!strings.Contains(d["held"].Reason, "Qualys: Scan Results") {
		t.Errorf("a digest holding fleet mail: %s %q", d["held"].Action, d["held"].Reason)
	}
	if d["heldold"].Action != ActionDelete {
		t.Errorf("after DigestKeep it goes: %s", d["heldold"].Action)
	}
	if d["noise"].Action != ActionDelete {
		t.Errorf("a digest of nothing the fleet reads goes on sight, held day or not: %s", d["noise"].Action)
	}
	if d["unread"].Action != ActionLeave || !strings.Contains(d["unread"].Reason, "could not be read") {
		t.Errorf("an unreadable digest stays: %s %q", d["unread"].Action, d["unread"].Reason)
	}
}
