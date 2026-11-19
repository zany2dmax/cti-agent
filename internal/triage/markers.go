package triage

// WHICH MAIL IS THREAT INTEL
//
// Anyone can send the threat-intel mailbox an advisory - a feed, a vendor, a
// colleague forwarding something they read - and anyone sends it other mail
// too: supplier requests, W9 threads, replies, auto-replies. The sender does
// not tell the two apart; the content does. IntelMarkers is what code can
// see without a model: a CVE ID, an ATT&CK technique ID, a defanged indicator
// or link, a public IP address, or a file hash written on its own. A message
// with none of them, from a sender not on TRIAGE_SENDERS, is never sent to a
// model. One that has them goes to the reader, which may still find nothing,
// and then the judge is not asked.

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// standaloneHashRE is an MD5, SHA-1 or SHA-256 on its own: not inside a
// link, a path or a longer token, where 32 hex characters are a session ID.
var standaloneHashRE = regexp.MustCompile(`(?i)(?:^|[\s,;:(\[])((?:[a-f0-9]{64})|(?:[a-f0-9]{40})|(?:[a-f0-9]{32}))(?:$|[\s,;:)\].])`)

// IntelMarkers says what in body looks like threat intel, one short reason
// each, or nothing.
func IntelMarkers(body string) []string {
	ex := Extract(body)
	var why []string
	add := func(n int, what string) {
		if n > 0 {
			why = append(why, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(len(ex.CVEs), "CVE ID(s)")
	add(len(ex.Techniques), "ATT&CK ID(s)")
	defanged, public := 0, 0
	for _, i := range ex.Indicators {
		if a, err := netip.ParseAddr(i); err == nil {
			if !a.IsPrivate() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsLinkLocalUnicast() {
				public++
			}
			continue
		}
		defanged++
	}
	add(defanged, "defanged indicator(s)")
	add(public, "public IP address(es)")
	hx := 0
	for _, l := range ex.Links {
		if strings.HasPrefix(strings.ToLower(l), "hxxp") {
			hx++
		}
	}
	add(hx, "defanged link(s)")
	add(len(standaloneHashRE.FindAllStringSubmatch(urlRE.ReplaceAllString(body, " "), 200)), "file hash(es)")
	return why
}
