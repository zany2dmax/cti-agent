package netmap

import (
	"net/netip"
	"strings"
	"testing"
)

var sample = [][]string{
	{"Location", "Network", "Mask/VLAN", "Gateway"},
	{"Alpha Site - ST - 10.1.0.0/16"},
	{"internet", "203.0.113.10", "255.255.255.252"},
	{"corp", "10.1.30.0/24", "vlan1"},
	{"10.1.30.1", "firewall"},
	{"", "an address note"},
	{"guest", "10.1.20.0/24", "vlan20"},
	{"Beta Site - ST - 10.2.0.0/16"},
	{"corp", "10.2.30.0 /24", "vlan1"},
	{"Gamma Site - 10.3.0.0/16"},
	{"corp", "10.3.30", "vlan1"},
	{"Delta Site - 10.4.0.0/16"},
	{"security", "10.4.210.0/24", "vlan210"},
	{"DECOMMISSIONED Epsilon - 10.5.0.0/16"},
	{"corp", "10.5.30.0/24", "vlan1"},
	{"Zeta Site - 10.6.0.0/16"},
	{"corp", "10.2.30.0/24", "vlan1"},
	{"Eta Site - 10.17.0.0/16"},
	{"inside", "10.17.30.0/24", "vlan30"},
}

func TestParsesTheLayoutPeopleWriteNotATable(t *testing.T) {
	subs := ParseSites(sample)
	got := map[string]Subnet{}
	for _, s := range subs {
		got[s.Location+"|"+s.Role] = s
	}
	if s := got["Alpha Site - ST - 10.1.0.0/16|corp"]; !s.Valid || s.Prefix.String() != "10.1.30.0/24" {
		t.Errorf("alpha corp = %+v", s)
	}
	for _, s := range subs {
		if s.Role == "internet" {
			t.Error("a public internet row was read as a network")
		}
		if s.Raw == "firewall" || s.Raw == "an address note" {
			t.Errorf("a device or note row became a subnet: %+v", s)
		}
	}
	if s := got["Beta Site - ST - 10.2.0.0/16|corp"]; !s.Valid || s.Prefix.String() != "10.2.30.0/24" {
		t.Errorf("a stray space before the mask: %+v", s)
	}
	if s := got["Gamma Site - 10.3.0.0/16|corp"]; s.Valid {
		t.Errorf("10.3.30 is not a network: %+v", s)
	}
	if s := got["DECOMMISSIONED Epsilon - 10.5.0.0/16|corp"]; !s.Inactive {
		t.Error("a decommissioned location is not marked inactive")
	}
}

func TestOnlyClearCorpNetworksAreSelectedAndTheRestBecomeQuestions(t *testing.T) {
	corp, qs := SelectCorp(ParseSites(sample), Rules{})
	var have []string
	for _, c := range corp {
		have = append(have, c.Location+"="+c.Subnet.Prefix.String())
	}
	// Eta labels its 10.17.30 network "inside": the 10.X.30 convention picks
	// it without a rule.
	if len(corp) != 3 || !strings.HasPrefix(have[0], "Alpha Site") || !strings.HasPrefix(have[1], "Beta Site") ||
		have[2] != "Eta Site - 10.17.0.0/16=10.17.30.0/24" {
		t.Errorf("corp = %v", have)
	}
	why := map[string]string{}
	for _, q := range qs {
		why[q.Location] = q.Why
	}
	if !strings.Contains(why["Gamma Site - 10.3.0.0/16"], "not a valid network") {
		t.Errorf("gamma: %q", why["Gamma Site - 10.3.0.0/16"])
	}
	if !strings.Contains(why["Delta Site - 10.4.0.0/16"], "no row counts") {
		t.Errorf("delta: %q", why["Delta Site - 10.4.0.0/16"])
	}
	// Zeta's header says 10.6.0.0/16 but its corp row is Beta's network: a typo
	// in the sheet, found because the network is outside the location's block.
	if !strings.Contains(why["Zeta Site - 10.6.0.0/16"], "outside the location's own block") {
		t.Errorf("zeta: %q", why["Zeta Site - 10.6.0.0/16"])
	}
	if _, ok := why["DECOMMISSIONED Epsilon - 10.5.0.0/16"]; ok {
		t.Error("a decommissioned location was asked about")
	}
}

func TestTwoLocationsClaimingTheSameNetworkAreBothAskedAbout(t *testing.T) {
	rows := [][]string{
		{"Theta Site - 10.8.0.0/16"}, {"corp", "10.8.30.0/24", "vlan1"},
		{"Iota Site - 10.8.0.0/16"}, {"corp", "10.8.30.0/24", "vlan1"},
	}
	corp, qs := SelectCorp(ParseSites(rows), Rules{})
	if len(corp) != 0 || len(qs) != 2 {
		t.Fatalf("corp %v, questions %v", corp, qs)
	}
	for _, q := range qs {
		if !strings.Contains(q.Why, "overlaps") {
			t.Errorf("question %+v", q)
		}
	}
}

// Seen in the real sheet: a role label with nothing beside it is a row somebody
// has not filled in, not a new location.
func TestAnEmptyRoleRowIsNotASiteHeader(t *testing.T) {
	rows := [][]string{
		{"Kappa Site - 10.9.0.0/16"}, {"internet"}, {"corp", "10.9.30.0/24", "vlan30"},
	}
	subs := ParseSites(rows)
	if len(subs) != 1 || subs[0].Location != "Kappa Site - 10.9.0.0/16" {
		t.Fatalf("subs = %+v", subs)
	}
}

func TestACorpRowWithNoNetworkSaysSo(t *testing.T) {
	rows := [][]string{{"Lambda Site - 10.10.0.0/16"}, {"corp", "", "vlan1"}, {"guest", "10.10.20.0/24", "vlan20"}}
	_, qs := SelectCorp(ParseSites(rows), Rules{})
	if len(qs) != 1 || !strings.Contains(qs[0].Why, "no network written") {
		t.Errorf("questions = %+v", qs)
	}
}

// A location whose corp network is outside its header's block is asked about
// until an operator rule says it is meant (HQ-style addressing).
func TestACorpNetworkOutsideItsBlockIsAskedAboutUntilARuleSaysItIsMeant(t *testing.T) {
	rows := [][]string{{"Mu Site - 10.11.0.0/16"}, {"corp", "192.168.5.0/24", "vlan1"}}
	if corp, qs := SelectCorp(ParseSites(rows), Rules{}); len(corp) != 0 || len(qs) != 1 || !strings.Contains(qs[0].Why, "outside") {
		t.Errorf("without a rule: %v %v", corp, qs)
	}
	r, _ := ParseRules("Mu Site | use corp")
	if corp, qs := SelectCorp(ParseSites(rows), r); len(corp) != 1 || len(qs) != 0 {
		t.Errorf("with a rule: %v %v", corp, qs)
	}
}

func TestAnOperatorRuleAnswersTheQuestion(t *testing.T) {
	r, problems := ParseRules("# comment\nEta Site | use inside,corp\nDelta Site | ignore\nbroken line\nZeta | use\n")
	if len(problems) != 2 {
		t.Fatalf("problems = %v", problems)
	}
	corp, qs := SelectCorp(ParseSites(sample), r)
	have := map[string]bool{}
	for _, c := range corp {
		have[c.Subnet.Prefix.String()] = true
	}
	if !have["10.17.30.0/24"] {
		t.Errorf("the rule did not make 'inside' count: %v", have)
	}
	for _, q := range qs {
		if strings.HasPrefix(q.Location, "Delta") || strings.HasPrefix(q.Location, "Eta") {
			t.Errorf("a ruled location is still a question: %+v", q)
		}
	}
}

func pfx(t *testing.T, s string) Range {
	t.Helper()
	return PrefixRange(netip.MustParsePrefix(s))
}

func rng(t *testing.T, s string) Range {
	t.Helper()
	r, err := ParseRange(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRangesMergeAndCoverAcrossGroups(t *testing.T) {
	// A /24 split across two groups is covered; half of one is partial.
	m := Merge([]Range{rng(t, "10.1.30.0-10.1.30.127"), rng(t, "10.1.30.128-10.1.30.255")})
	if len(m) != 1 || coverage(m, pfx(t, "10.1.30.0/24")) != full {
		t.Errorf("merged = %v", m)
	}
	if coverage(Merge([]Range{rng(t, "10.1.30.0-10.1.30.127")}), pfx(t, "10.1.30.0/24")) != partial {
		t.Error("half a network is not partial")
	}
	if coverage(Merge([]Range{rng(t, "10.9.0.1")}), pfx(t, "10.1.30.0/24")) != none {
		t.Error("an unrelated address covers")
	}
	for _, bad := range []string{"10.1.1.9-10.1.1.2", "banana", "10.1.1.0/24", "::1"} {
		if _, err := ParseRange(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestTheCheckFindsTheGapsInEveryDirection(t *testing.T) {
	corp := []Corp{
		{"Covered", Subnet{Prefix: netip.MustParsePrefix("10.1.30.0/24"), Valid: true}},
		{"Split across groups", Subnet{Prefix: netip.MustParsePrefix("10.2.30.0/24"), Valid: true}},
		{"Missed entirely", Subnet{Prefix: netip.MustParsePrefix("10.3.30.0/24"), Valid: true}},
		{"Grouped but unscanned", Subnet{Prefix: netip.MustParsePrefix("10.4.30.0/24"), Valid: true}},
		{"Half covered", Subnet{Prefix: netip.MustParsePrefix("10.5.30.0/24"), Valid: true}},
	}
	var all []Subnet
	for _, c := range corp {
		all = append(all, c.Subnet)
	}
	groups := []Group{
		{Title: "Alpha", Ranges: []Range{rng(t, "10.1.30.0-10.1.30.255")}},
		{Title: "Beta one", Ranges: []Range{rng(t, "10.2.30.0-10.2.30.127")}},
		{Title: "Beta two", Ranges: []Range{rng(t, "10.2.30.128-10.2.30.255")}},
		{Title: "Delta", Ranges: []Range{rng(t, "10.4.30.0-10.4.30.255")}},
		{Title: "Epsilon", Ranges: []Range{rng(t, "10.5.30.0-10.5.30.127")}},
		{Title: "Mystery", Ranges: []Range{rng(t, "172.30.0.0-172.30.0.255")}},
		{Title: "Empty"},
	}
	scanned := []string{"Alpha", "\ufeffBeta one", "BETA TWO", "Epsilon", "Mystery", "Empty", "No Such Group"}
	res := Check(corp, all, groups, scanned)
	kinds := map[Kind][]string{}
	for _, f := range res.Findings {
		kinds[f.Kind] = append(kinds[f.Kind], f.Location+f.Group)
	}
	if res.Checked != 5 || res.Covered != 2 {
		t.Errorf("checked %d covered %d", res.Checked, res.Covered)
	}
	want := map[Kind]string{
		NotInAnyGroup:      "Missed entirely",
		GroupNotScanned:    "Grouped but unscanned",
		PartlyCovered:      "Half covered",
		ScannedNotInSheet:  "Mystery",
		UnknownTargetGroup: "No Such Group",
	}
	for k, w := range want {
		found := false
		for _, v := range kinds[k] {
			if strings.Contains(v, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no finding for %q in %v", k, w, kinds[k])
		}
	}
	// The empty group is reported as unverifiable, not as fine.
	if !strings.Contains(strings.Join(kinds[ScannedNotInSheet], " "), "Empty") {
		t.Errorf("an Asset Group with no ranges passed silently: %v", kinds[ScannedNotInSheet])
	}
}

func TestParsesQualysAssetGroupsAndRefusesATruncatedList(t *testing.T) {
	ok := `<?xml version="1.0"?><ASSET_GROUP_LIST_OUTPUT><RESPONSE><DATETIME>x</DATETIME><ASSET_GROUP_LIST>
<ASSET_GROUP><ID>1</ID><TITLE>Alpha</TITLE><IP_SET><IP>10.1.30.5</IP><IP_RANGE>10.1.31.0-10.1.31.255</IP_RANGE></IP_SET></ASSET_GROUP>
<ASSET_GROUP><ID>2</ID><TITLE> Beta </TITLE><IP_SET><IP_RANGE>10.2.30.0-10.2.30.255,10.2.40.0-10.2.40.9</IP_RANGE><IP_RANGE>fe80::1-fe80::9</IP_RANGE></IP_SET></ASSET_GROUP>
<ASSET_GROUP><ID>3</ID><TITLE>Empty</TITLE></ASSET_GROUP>
</ASSET_GROUP_LIST></RESPONSE></ASSET_GROUP_LIST_OUTPUT>`
	gs, err := ParseGroups([]byte(ok))
	if err != nil || len(gs) != 3 {
		t.Fatalf("%v %v", gs, err)
	}
	if gs[1].Title != "Beta" || len(gs[1].Ranges) != 2 {
		t.Errorf("beta = %+v (the IPv6 range is skipped, the comma list split)", gs[1])
	}
	if len(gs[0].Ranges) != 2 || len(gs[2].Ranges) != 0 {
		t.Errorf("alpha %+v empty %+v", gs[0], gs[2])
	}
	trunc := `<ASSET_GROUP_LIST_OUTPUT><RESPONSE><ASSET_GROUP_LIST></ASSET_GROUP_LIST><WARNING><CODE>1980</CODE><TEXT>1000 record limit exceeded</TEXT><URL>x</URL></WARNING></RESPONSE></ASSET_GROUP_LIST_OUTPUT>`
	if _, err := ParseGroups([]byte(trunc)); err == nil || !strings.Contains(err.Error(), "partial list") {
		t.Errorf("a truncated list was accepted: %v", err)
	}
	denied := `<ASSET_GROUP_LIST_OUTPUT><RESPONSE><CODE>2002</CODE><TEXT>Access denied</TEXT></RESPONSE></ASSET_GROUP_LIST_OUTPUT>`
	if _, err := ParseGroups([]byte(denied)); err == nil {
		t.Error("an error response was accepted as an empty list")
	}
}

func TestPrefixRangeEdges(t *testing.T) {
	for _, c := range []struct {
		cidr   string
		lo, hi uint32
	}{
		{"10.1.30.0/24", 0x0A011E00, 0x0A011EFF},
		{"10.1.30.7/32", 0x0A011E07, 0x0A011E07},
		{"0.0.0.0/0", 0, 0xFFFFFFFF},
		{"255.255.255.255/32", 0xFFFFFFFF, 0xFFFFFFFF},
		{"192.168.0.0/16", 0xC0A80000, 0xC0A8FFFF},
		{"10.1.30.130/25", 0x0A011E80, 0x0A011EFF}, // a host address is masked first
	} {
		r := PrefixRange(netip.MustParsePrefix(c.cidr))
		if r.Lo != c.lo || r.Hi != c.hi {
			t.Errorf("%s = %08x-%08x, want %08x-%08x", c.cidr, r.Lo, r.Hi, c.lo, c.hi)
		}
	}
}

// The cases from the real sheet (2026-11-17), with invented names.
func TestTheTenX30NetworkIsPickedWhateverItsLabel(t *testing.T) {
	rows := [][]string{
		// HQ: corp is a 192.168 /23, the 10.6.30 network is labelled "inside".
		{"Head Office - 10.6.0.0/16"}, {"corp", "192.168.0.0/23", "vlan1"}, {"inside", "10.6.30.0/24", "vlan30"},
		// No corp row at all; the 10.20.30 network is "Employee LAN".
		{"Cabinet Shop - 10.20.0.0/16"}, {"Servers", "10.20.10.0/24", "vlan10"},
		{"Employee LAN", "10.20.30.0/24", "vlan30"},
		// A setup row inside ANOTHER location's block, and its own corp row.
		{"Norcross Branch - 10.14.0.0/16"}, {"setup", "10.20.30.0/24", "vlan1"}, {"corp", "10.14.30.0/24", "vlan30"},
		// Sizes other than /24.
		{"Paper Mill - 10.45.0.0/16"}, {"corp", "10.45.30.0/23", "vlan1"},
		{"Small Branch - 10.62.0.0/16"}, {"corp", "10.62.30.0/26", "vlan30"},
		// A typo in the corp cell and nothing else at 10.27.30: still a question.
		{"Naples Branch - 10.27.0.0/16"}, {"corp", "10.29.30", "vlan1"},
	}
	corp, qs := SelectCorp(ParseSites(rows), Rules{})
	got := map[string]string{}
	for _, c := range corp {
		got[c.Location] += c.Subnet.Prefix.String() + " "
	}
	want := map[string]string{
		"Head Office - 10.6.0.0/16":      "10.6.30.0/24 ",
		"Cabinet Shop - 10.20.0.0/16":    "10.20.30.0/24 ",
		"Norcross Branch - 10.14.0.0/16": "10.14.30.0/24 ",
		"Paper Mill - 10.45.0.0/16":      "10.45.30.0/23 ",
		"Small Branch - 10.62.0.0/16":    "10.62.30.0/26 ",
	}
	for loc, w := range want {
		if got[loc] != w {
			t.Errorf("%s: got %q, want %q", loc, got[loc], w)
		}
	}
	if _, ok := got["Naples Branch - 10.27.0.0/16"]; ok {
		t.Error("an invalid corp cell must stay a question")
	}
	var naples bool
	for _, q := range qs {
		naples = naples || (q.Location == "Naples Branch - 10.27.0.0/16" && q.Kind == QInvalid)
	}
	if !naples {
		t.Errorf("questions: %+v", qs)
	}
}

func TestARuleStillDecidesOverTheConvention(t *testing.T) {
	rows := [][]string{{"Head Office - 10.6.0.0/16"}, {"corp", "192.168.0.0/23", "vlan1"}, {"inside", "10.6.30.0/24", "vlan30"}}
	rules, _ := ParseRules("Head Office | use corp,inside\n")
	corp, _ := SelectCorp(ParseSites(rows), rules)
	if len(corp) != 2 {
		t.Errorf("a 'use corp,inside' rule must check both networks: %+v", corp)
	}
}

func TestOnlyAHeaderThatStartsWithDecommissionedIsClosed(t *testing.T) {
	rows := [][]string{
		{"DECOMISSIONED - Old Branch - GA - 10.2.0.0/16"}, {"corp", "10.2.30.0/24", "vlan1"},
		{"Decommissioned?? - Maybe Branch - 10.35.0.0/16"}, {"corp", "10.35.30.0/24", "vlan1"},
		{"Charleston Store - 10.44.0.0/16 - Formally Old Store Decommissioned 8/1/2025"}, {"corp", "10.44.30.0/24", "vlan30"},
	}
	corp, _ := SelectCorp(ParseSites(rows), Rules{})
	if len(corp) != 1 || corp[0].Subnet.Prefix.String() != "10.44.30.0/24" {
		t.Errorf("only the open store should be checked: %+v", corp)
	}
}

// A scanned group that only holds a closed site, and a group no scan targets.
func TestCheckNamesGroupsOnDecommissionedSitesAndGroupsNoScanTargets(t *testing.T) {
	all := ParseSites([][]string{
		{"Open Branch - 10.4.0.0/16"}, {"corp", "10.4.30.0/24", "vlan1"},
		{"DECOMISSIONED - Old Branch - 10.2.0.0/16"}, {"corp", "10.2.30.0/24", "vlan1"},
		{"Idle Branch - 10.9.0.0/16"}, {"corp", "10.9.30.0/24", "vlan1"},
	})
	corp, _ := SelectCorp(all, Rules{})
	r := func(s string) Range { x, _ := ParseRange(s); return x }
	groups := []Group{
		{Title: "Open", Ranges: []Range{r("10.4.30.0-10.4.30.255")}},
		{Title: "Old", Ranges: []Range{r("10.2.30.0-10.2.30.255")}},
		{Title: "Idle", Ranges: []Range{r("10.9.30.0-10.9.30.255")}},
		{Title: "Empty label"},
	}
	res := Check(corp, all, groups, []string{"Open", "Old"})
	kinds := map[string]Kind{}
	for _, f := range res.Findings {
		kinds[f.Group+"|"+f.Location] = f.Kind
	}
	if kinds["Old|"] != ScannedDecommissioned {
		t.Errorf("the group on the closed site: %+v", res.Findings)
	}
	if kinds["Idle|"] != GroupNotTargeted {
		t.Errorf("the group no scan targets: %+v", res.Findings)
	}
	if _, ok := kinds["Empty label|"]; ok {
		t.Error("a group with no addresses is a label, not a network")
	}
	if kinds["Idle|Idle Branch - 10.9.0.0/16"] != GroupNotScanned {
		t.Errorf("the idle branch's network is still a gap: %+v", res.Findings)
	}
}

// The question text goes to the network team, in the email and the help-desk
// ticket; the rules file is the security team's, so the text never mentions it.
func TestQuestionsDoNotSendTheNetworkTeamToTheRulesFile(t *testing.T) {
	_, qs := SelectCorp(ParseSites(sample), Rules{})
	for _, q := range qs {
		if strings.Contains(strings.ToLower(q.Why), "rule") {
			t.Errorf("%s: %q", q.Location, q.Why)
		}
	}
}
