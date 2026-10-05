package qualys

import (
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// ScanMargin is how much earlier than the report window the scan list is
// fetched. Longer than the longest scan seen here, which runs well under a
// day; two days costs one larger response and nothing else.
const ScanMargin = 48 * time.Hour

// Reconciliation says what joining the mailbox to the scan list found.
//
// Every number here is something that would otherwise have been silent: a
// notification the API has no record of, or a scan the API ran whose email
// never arrived.
type Reconciliation struct {
	Matched int
	// Unmatched are scan references from notifications that the scan list did
	// not contain. Usually a scan launched before the API window; worth a
	// warning, never a reason to drop the notification's counts.
	Unmatched []string
	// Skipped counts scans deliberately left out: discovery scans, which test
	// nothing, and scans still running.
	Skipped int
}

// Reconcile joins notification results to the API scan list on the scan
// reference, and adds the vulnerability scans the mailbox never heard about.
//
// The reference is the join key because it is the one identifier both
// carry verbatim - the email prints "Scan Reference : was/..." and the API
// returns <reference>was/...</reference>. Not the application name: the email
// only has the scan title to derive one from, and on the real estate the
// title matched the application's actual name in almost no case.
//
// # WHAT THE API IS TRUSTED FOR, AND WHAT IT IS NOT
//
//   - Application identity: AppID and the real name. Always taken.
//   - Authentication: a FAILED authStatus is taken even if the email parse
//     missed it. The direction matters - the API can make a scan look worse,
//     never better. A notification that says it failed stays failed.
//   - Counts: NEVER. The scan list carries none. A scan with no notification
//     is added with NoNotification set and no counts, and the renderer lists
//     it separately rather than printing zeroes.
//
// # WHICH API SCANS ARE ADDED
//
// A scan with no notification is added only if it is a VULNERABILITY scan
// that has finished one way or the other, and only if its application has NO
// notified scan in the window. The last rule keeps a newer email-less run from
// displacing an older run whose counts we actually have; the application is
// reported from the scan we can describe.
//
// # THE WINDOW
//
// The caller fetches the scan list from EARLIER than since - see ScanMargin -
// because the mailbox window is by arrival and the scan list by launch. A
// long scan launched before the window and finished inside it is in the
// mailbox and would otherwise be missing from the list, leaving its
// notification unmatched. Email-less scans are only ADDED if they launched
// at or after since, so the margin widens the join without widening the
// report.
//
// # THE LINK
//
// portal is PortalOrigin(QUALYS_BASE_URL). When set, every result that
// matched or came from the scan list gets PortalURL = ScanReportURL(portal,
// id): built from the API's integer id, never copied from mail. Empty means
// no built links, and the renderer falls back to the email's link as text.
func Reconcile(results []appscan.ScanResult, scans []Scan, since time.Time, portal string) ([]appscan.ScanResult, Reconciliation) {
	var rec Reconciliation
	byRef := make(map[string]Scan, len(scans))
	for _, s := range scans {
		if s.Reference != "" {
			byRef[s.Reference] = s
		}
	}

	out := make([]appscan.ScanResult, 0, len(results)+len(scans))
	notified := map[string]bool{} // reference
	haveApp := map[string]bool{}  // AppID with a notified scan
	for _, r := range results {
		s, ok := byRef[r.Reference]
		if r.Provider != (Provider{}).Name() || r.Reference == "" || !ok {
			if r.Provider == (Provider{}).Name() && r.Reference != "" {
				rec.Unmatched = append(rec.Unmatched, r.Reference)
			}
			out = append(out, r)
			continue
		}
		rec.Matched++
		notified[r.Reference] = true
		r = applyScan(r, s)
		r.PortalURL = ScanReportURL(portal, s.ID)
		if r.AppID != "" {
			haveApp[r.AppID] = true
		}
		out = append(out, r)
	}

	for _, s := range scans {
		switch {
		case notified[s.Reference]:
			continue
		case s.Type != "VULNERABILITY" || s.InFlight():
			rec.Skipped++
			continue
		case s.WebAppID != "" && haveApp[s.WebAppID]:
			continue
		case !since.IsZero() && s.Launched.Before(since):
			// Fetched only so a notification could match it.
			continue
		}
		r := fromScan(s)
		r.PortalURL = ScanReportURL(portal, s.ID)
		if r.Fault() && s.Mode != "SCHEDULED" {
			// An on-demand run that was cancelled, or whose login failed, with
			// no notification: somebody at the console, troubleshooting. The
			// real scan list has a run of exactly these against one staging
			// application. Raising each as a SCANNER FAULT - and alerting the
			// operator about their own test runs - is noise. A SCHEDULED run
			// failing is the case that matters: authentication normally
			// happens there, and nobody is watching it.
			rec.Skipped++
			continue
		}
		out = append(out, r)
	}
	return out, rec
}

// applyScan takes the API's identity and any authentication failure onto a
// notified result.
func applyScan(r appscan.ScanResult, s Scan) appscan.ScanResult {
	r.AppID = s.WebAppID
	if s.WebAppName != "" {
		r.App = s.WebAppName
	}
	if r.Target == "" {
		r.Target = s.WebAppURL
	}
	if strings.EqualFold(s.AuthStatus, "FAILED") && !r.Auth.Failed() {
		// Only ever worse. Record the API's word for it so the fault line
		// says where the verdict came from.
		r.Auth.Status = "Failed (per the Qualys WAS scan list)"
		if r.Auth.Record == "" {
			r.Auth.Record = s.AuthRecord
		}
	}
	return r
}

// fromScan builds a result for a scan whose notification never arrived.
//
// Identity, status and authentication only. The counts are left zero AND the
// result is flagged NoNotification, which is what stops those zeroes being
// read as anything.
func fromScan(s Scan) appscan.ScanResult {
	return appscan.ScanResult{
		Provider:       (Provider{}).Name(),
		App:            s.WebAppName,
		AppID:          s.WebAppID,
		ScanTitle:      s.Name,
		Reference:      s.Reference,
		Target:         s.WebAppURL,
		Started:        s.Launched,
		Status:         s.Status,
		Complete:       s.Complete(),
		LinksCrawled:   s.LinksCrawled,
		Auth:           apiAuth(s),
		NoNotification: true,
	}
}

// apiAuth translates the API's NONE/SUCCESSFUL/FAILED into the vocabulary
// appscan.Auth already reads, so Failed() and Label() behave identically
// whichever source a result came from.
//
// NONE with a record configured comes out as Failed() - the record is there
// and the scan did not authenticate. That is the "authentication normally
// happens here and did not" case, whatever the vendor calls it.
func apiAuth(s Scan) appscan.Auth {
	switch strings.ToUpper(s.AuthStatus) {
	case "SUCCESSFUL":
		return appscan.Auth{Record: s.AuthRecord, Status: "Successful"}
	case "FAILED":
		return appscan.Auth{Record: s.AuthRecord, Status: "Failed"}
	}
	return appscan.Auth{Record: s.AuthRecord, Status: "No Authentication specified"}
}
