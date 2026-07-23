package api

import (
	"encoding/json"
	"strings"

	"github.com/reloadlife/wireguardd/internal/wgbackend"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func encodeAmnezia(p *pkgapi.AmneziaParams) string {
	if p == nil {
		return ""
	}
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	s := string(b)
	if s == "{}" || s == "null" {
		return ""
	}
	return s
}

func decodeAmnezia(s string) *pkgapi.AmneziaParams {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" || s == "null" {
		return nil
	}
	var p pkgapi.AmneziaParams
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil
	}
	return &p
}

func toBackendAmnezia(p *pkgapi.AmneziaParams) wgbackend.AmneziaParams {
	if p == nil {
		return wgbackend.AmneziaParams{}
	}
	return wgbackend.AmneziaParams{
		Jc: p.Jc, Jmin: p.Jmin, Jmax: p.Jmax,
		S1: p.S1, S2: p.S2, S3: p.S3, S4: p.S4,
		H1: p.H1, H2: p.H2, H3: p.H3, H4: p.H4,
		I1: p.I1, I2: p.I2, I3: p.I3, I4: p.I4, I5: p.I5,
	}
}

func fromBackendAmnezia(p wgbackend.AmneziaParams) *pkgapi.AmneziaParams {
	// Always return a pointer for generated presets (even when only H set).
	return &pkgapi.AmneziaParams{
		Jc: p.Jc, Jmin: p.Jmin, Jmax: p.Jmax,
		S1: p.S1, S2: p.S2, S3: p.S3, S4: p.S4,
		H1: p.H1, H2: p.H2, H3: p.H3, H4: p.H4,
		I1: p.I1, I2: p.I2, I3: p.I3, I4: p.I4, I5: p.I5,
	}
}
