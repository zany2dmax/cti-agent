package netmap

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// buildXLSX writes a minimal workbook with the given sheets: shared strings for
// text, the way Excel does, plus one inline string to cover both.
func buildXLSX(t *testing.T, sheets map[string][][]string, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	var shared []string
	idx := map[string]int{}
	si := func(s string) int {
		if i, ok := idx[s]; ok {
			return i
		}
		idx[s] = len(shared)
		shared = append(shared, s)
		return idx[s]
	}
	var wb, rels strings.Builder
	wb.WriteString(`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	rels.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for n, name := range order {
		fmt.Fprintf(&wb, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, name, n+1, n+1)
		fmt.Fprintf(&rels, `<Relationship Id="rId%d" Target="worksheets/sheet%d.xml"/>`, n+1, n+1)
		var sd strings.Builder
		sd.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
		for r, row := range sheets[name] {
			fmt.Fprintf(&sd, `<row r="%d">`, r+1)
			for c, v := range row {
				if v == "" {
					continue
				}
				ref := fmt.Sprintf("%c%d", 'A'+c, r+1)
				if v == "INLINE" {
					fmt.Fprintf(&sd, `<c r="%s" t="inlineStr"><is><t>inline text</t></is></c>`, ref)
					continue
				}
				fmt.Fprintf(&sd, `<c r="%s" t="s"><v>%d</v></c>`, ref, si(v))
			}
			sd.WriteString(`</row>`)
		}
		sd.WriteString(`</sheetData></worksheet>`)
		add(fmt.Sprintf("xl/worksheets/sheet%d.xml", n+1), sd.String())
	}
	wb.WriteString(`</sheets></workbook>`)
	rels.WriteString(`</Relationships>`)
	add("xl/workbook.xml", wb.String())
	add("xl/_rels/workbook.xml.rels", rels.String())
	var sst strings.Builder
	sst.WriteString(`<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	for _, s := range shared {
		fmt.Fprintf(&sst, `<si><t>%s</t></si>`, s)
	}
	sst.WriteString(`</sst>`)
	add("xl/sharedStrings.xml", sst.String())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

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
	{"Eta Site - 10.7.0.0/16"},
	{"inside", "REDACTED-IP/24", "vlan30"},
}

func TestReadsSheetsByNameAndKeepsTextAndInlineCells(t *testing.T) {
	x := buildXLSX(t, map[string][][]string{"Sites": sample, "Home": {{"INLINE", "x"}}}, []string{"Sites", "Home"})
	rows, err := ReadSheet(x, "sites")
	if err != nil || len(rows) != len(sample) {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	if rows[3][0] != "corp" || rows[3][1] != "10.1.30.0/24" {
		t.Errorf("row 3 = %v", rows[3])
	}
	home, _ := ReadSheet(x, "Home")
	if home[0][0] != "inline text" {
		t.Errorf("inline = %v", home)
	}
	if _, err := ReadSheet(x, "Nope"); err == nil || !strings.Contains(err.Error(), "Sites, Home") {
		t.Errorf("a missing sheet should name the ones there: %v", err)
	}
	if _, err := ReadSheet([]byte("not a zip"), "Sites"); err == nil {
		t.Error("garbage was accepted as a workbook")
	}
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
	if len(corp) != 1 || !strings.HasPrefix(have[0], "Alpha Site") {
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
	// Beta and Zeta claim the same network, so neither is acted on.
	if !strings.Contains(why["Beta Site - ST - 10.2.0.0/16"], "overlaps") || !strings.Contains(why["Zeta Site - 10.6.0.0/16"], "overlaps") {
		t.Errorf("overlap questions: %v", why)
	}
	if _, ok := why["DECOMMISSIONED Epsilon - 10.5.0.0/16"]; ok {
		t.Error("a decommissioned location was asked about")
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
	if !have["REDACTED-IP/24"] {
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
