package enrich

import (
	"bytes"
	"encoding/json"
)

// NVDEntry is what NVD says about one CVE, as kept in state/nvd-cache.json.
// The score is a json.Number so it is written back as NVD wrote it (10.0
// stays 10.0). Pointers are null in the JSON when NVD has no value.
type NVDEntry struct {
	CVSS         *json.Number `json:"cvss"`
	CVSSSeverity *string      `json:"cvss_severity"`
	Description  *string      `json:"description"`
	KEVNVD       bool         `json:"kev_nvd"`
	VulnStatus   *string      `json:"vuln_status"`
	Published    *string      `json:"published"`
	CPEProducts  *[][]string  `json:"cpe_products"` // nil: cached before the field existed
}

// EPSSEntry is FIRST's exploitation probability for one CVE.
type EPSSEntry struct {
	EPSS float64 `json:"epss"`
	Pct  float64 `json:"epss_pct"`
	Date *string `json:"epss_date"`
}

// KEVEntry is one CISA KEV catalog entry, as kept in state/kev-cache.json
// (which internal/kev also reads). Every field can be null in the catalog.
type KEVEntry struct {
	Added      *string `json:"kev_added"`
	Due        *string `json:"kev_due"`
	Ransomware *string `json:"ransomware"`
	Name       *string `json:"kev_name"`
	Action     *string `json:"kev_action"`
	Vendor     *string `json:"kev_vendor"`
	Product    *string `json:"kev_product"`
	hasVendor  bool    // the cache entry had the kev_vendor key
}

// UnmarshalJSON records whether kev_vendor was present: a cache written
// before it existed is refetched once, or product names would be missing.
func (k *KEVEntry) UnmarshalJSON(b []byte) error {
	type plain KEVEntry
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	*k = KEVEntry(p)
	_, k.hasVendor = keys["kev_vendor"]
	return nil
}

// Finding is one CVE through enrichment. It is written to the enriched file
// with the same keys, in the same order, as it always has been: cti-brief,
// cti-jira and fleet-db read it.
type Finding struct {
	CVE            string
	Status         string
	Provider       string
	QIDs           string
	HostCount      int
	QualysScore    int
	LastSeen       string
	SampleHosts    string
	ProviderReason string

	// From the report only; --cves findings have none of these keys.
	FromReport      bool
	DetectionTitles []string
	MailSource      string
	Asked           bool

	NVD  *NVDEntry  // nil: no NVD data, and none of its keys
	EPSS *EPSSEntry // nil: no score, and none of its keys
	KEV  *KEVEntry  // nil: not in the catalog, and none of its keys

	KEVFlag       int // 1 when on KEV (the catalog, or NVD's flag without it)
	KEVDaysLeft   *int
	Priority      string
	Rationale     string
	Product       string
	ProductSource string
	IsNew         *bool   // nil: no history to compare against
	FirstSeen     *string // when the findings database first stored it
}

func (f *Finding) score() scoreInput {
	s := scoreInput{Status: f.Status, HostCount: f.HostCount, KEV: f.KEVFlag != 0}
	if f.EPSS != nil {
		s.EPSS = f.EPSS.EPSS
	}
	if f.NVD != nil && f.NVD.CVSS != nil {
		s.CVSS = *f.NVD.CVSS
	}
	if f.KEV != nil {
		s.KEVDue, s.Ransomware = f.KEV.Due, f.KEV.Ransomware
	}
	return s
}

func (f *Finding) product() (string, string) {
	var vendor, product string
	if f.KEV != nil {
		vendor, product = deref(f.KEV.Vendor), deref(f.KEV.Product)
	}
	var cpe [][]string
	if f.NVD != nil && f.NVD.CPEProducts != nil {
		cpe = *f.NVD.CPEProducts
	}
	return ProductFor(vendor, product, cpe, f.DetectionTitles, f.Provider)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// object writes JSON keys in the order they are added.
type object struct {
	buf bytes.Buffer
	err error
}

func (o *object) add(key string, v any) {
	if o.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		o.err = err
		return
	}
	if o.buf.Len() == 0 {
		o.buf.WriteByte('{')
	} else {
		o.buf.WriteByte(',')
	}
	k, _ := json.Marshal(key)
	o.buf.Write(k)
	o.buf.WriteByte(':')
	o.buf.Write(b)
}

func (o *object) bytes() ([]byte, error) {
	if o.err != nil {
		return nil, o.err
	}
	if o.buf.Len() == 0 {
		return []byte("{}"), nil
	}
	o.buf.WriteByte('}')
	return o.buf.Bytes(), nil
}

// MarshalJSON writes the finding's keys in the order the enriched file has
// always had them, with a source's keys present only when it answered.
func (f *Finding) MarshalJSON() ([]byte, error) {
	var o object
	o.add("cve", f.CVE)
	o.add("status", f.Status)
	o.add("provider", f.Provider)
	o.add("qids", f.QIDs)
	o.add("host_count", f.HostCount)
	o.add("qualys_score", f.QualysScore)
	o.add("last_seen", f.LastSeen)
	o.add("sample_hosts", f.SampleHosts)
	o.add("provider_reason", f.ProviderReason)
	if f.FromReport {
		o.add("detection_titles", nonNil(f.DetectionTitles))
		o.add("mail_source", f.MailSource)
		o.add("asked", f.Asked)
	}
	if n := f.NVD; n != nil {
		o.add("cvss", n.CVSS)
		o.add("cvss_severity", n.CVSSSeverity)
		o.add("description", n.Description)
		o.add("vuln_status", n.VulnStatus)
		o.add("published", n.Published)
		if n.CPEProducts != nil {
			o.add("cpe_products", *n.CPEProducts)
		}
	}
	if e := f.EPSS; e != nil {
		o.add("epss", e.EPSS)
		o.add("epss_pct", e.Pct)
		o.add("epss_date", e.Date)
	}
	o.add("kev", f.KEVFlag)
	if k := f.KEV; k != nil {
		o.add("kev_added", k.Added)
		o.add("kev_due", k.Due)
		o.add("ransomware", k.Ransomware)
		o.add("kev_name", k.Name)
		o.add("kev_action", k.Action)
		o.add("kev_vendor", k.Vendor)
		o.add("kev_product", k.Product)
	}
	o.add("kev_days_left", f.KEVDaysLeft)
	o.add("priority", f.Priority)
	o.add("rationale", f.Rationale)
	o.add("product", f.Product)
	o.add("product_source", f.ProductSource)
	o.add("is_new", f.IsNew)
	o.add("first_seen", f.FirstSeen)
	return o.bytes()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Meta is the report's header facts, in the order they are written.
type Meta [][2]string

// MarshalJSON writes the facts as one object, in order.
func (m Meta) MarshalJSON() ([]byte, error) {
	var o object
	for _, kv := range m {
		o.add(kv[0], kv[1])
	}
	return o.bytes()
}

// Counts is the number of findings in each band, Sev5 first.
type Counts map[string]int

// MarshalJSON writes every band, most urgent first.
func (c Counts) MarshalJSON() ([]byte, error) {
	var o object
	for _, p := range SevOrder {
		o.add(p, c[p])
	}
	return o.bytes()
}

// Novelty says what changed since the last run. Undetermined is how many
// findings could not be compared: no findings database yet.
type Novelty struct {
	New          int      `json:"new"`
	SeenBefore   int      `json:"seen_before"`
	Undetermined int      `json:"undetermined"`
	NewCVEs      []string `json:"new_cves"`
}

// Result is the enriched file, cti-enriched in all but name: cti-brief,
// cti-jira, cti-kev and the weekly read it.
type Result struct {
	Generated     string     `json:"generated"`
	SourceMeta    Meta       `json:"source_meta"`
	Counts        Counts     `json:"counts"`
	Total         int        `json:"total"`
	Degraded      []string   `json:"degraded"`
	KEVDeadlines  KEVSummary `json:"kev_deadlines"`
	EmailSubjects []Subject  `json:"email_subjects"`
	Novelty       Novelty    `json:"novelty"`
	Findings      []*Finding `json:"findings"`

	kev map[string]KEVEntry // the catalog, for SaveProducts
}
