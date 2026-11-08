package appscan

import (
	"regexp"
	"strings"
	"time"
)

// ScheduledNoticeReader is implemented by a provider whose scanner also mails
// a "scan starts soon" notice ahead of each scheduled run.
//
// The notice carries nothing the weekly uses. Once the weekly has reported on
// the run it announced, the lane claims it for the mailbox cleanup to DELETE
// (mailbox.Processed.Delete) - the operator's call - instead of leaving it in
// the inbox for good. It is matched to a run, never claimed on its subject:
// see ScheduledFor.
type ScheduledNoticeReader interface {
	// RecognisesScheduled is true for the scanner's own notice, by sender
	// domain exactly and subject prefix, like Provider.Recognises.
	RecognisesScheduled(sender, subject string) bool
	// ParseScheduled returns the scan title and the launch time the notice
	// announces; zero values when it carries neither.
	ParseScheduled(body string) (title string, launch time.Time)
}

// runSuffixRE is the " Run #41" the scanner appends to a schedule's title to
// name one run of it.
var runSuffixRE = regexp.MustCompile(`(?i)\s+run\s*#\s*\d+\s*$`)

// scheduledSlack is how far a run's start may sit from the launch time its
// notice announced: a little before (clock skew between the scheduler and
// the scan), or a few hours after (a queued scan waits for a scanner).
const (
	scheduledEarly = 10 * time.Minute
	scheduledLate  = 6 * time.Hour
)

// ScheduledFor reports whether a scheduled notice for title, launching at
// launch, announced this run. The title must equal the run's title less its
// " Run #N", and the run must have started within the slack of the launch.
// Anything missing matches nothing.
func ScheduledFor(title string, launch time.Time, s ScanResult) bool {
	if strings.TrimSpace(title) == "" || launch.IsZero() || s.Started.IsZero() {
		return false
	}
	name := strings.Join(strings.Fields(runSuffixRE.ReplaceAllString(s.ScanTitle, "")), " ")
	if !strings.EqualFold(name, strings.Join(strings.Fields(title), " ")) {
		return false
	}
	d := s.Started.Sub(launch)
	return d >= -scheduledEarly && d <= scheduledLate
}
