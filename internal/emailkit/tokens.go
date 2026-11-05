package emailkit

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// tokens.json is the one definition of the fleet's colours and font. Go reads
// it here; brief.py (Python cannot import this package) reads a copy at
// fleet-kit/fleet/lanes/email-tokens.json, and emailkit_test.go fails the
// build when the two differ. Change the look in internal/emailkit/tokens.json,
// then copy it over the lanes file.
//
//go:embed tokens.json
var tokensJSON []byte

type toneJSON struct {
	Fg string `json:"fg"`
	Bg string `json:"bg"`
}

type tokenFile struct {
	Font     string              `json:"font"`
	Mono     string              `json:"mono"`
	PageBG   string              `json:"page_bg"`
	Navy     string              `json:"navy"`
	BandText string              `json:"band_text"`
	Ink      string              `json:"ink"`
	Soft     string              `json:"soft"`
	Muted    string              `json:"muted"`
	Rule     string              `json:"rule"`
	Tones    map[string]toneJSON `json:"tones"`
}

var tok = func() tokenFile {
	var t tokenFile
	if err := json.Unmarshal(tokensJSON, &t); err != nil {
		panic("emailkit: tokens.json does not parse: " + err.Error())
	}
	return t
}()

func tone(name string) Tone {
	t, ok := tok.Tones[name]
	if !ok || t.Fg == "" || t.Bg == "" {
		panic(fmt.Sprintf("emailkit: tokens.json has no tone %q", name))
	}
	return Tone(t)
}
