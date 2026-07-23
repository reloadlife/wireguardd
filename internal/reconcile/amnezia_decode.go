package reconcile

import (
	"encoding/json"
	"strings"

	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

func decodeAmneziaJSONImpl(s string) wgbackend.AmneziaParams {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" || s == "null" {
		return wgbackend.AmneziaParams{}
	}
	var p wgbackend.AmneziaParams
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return wgbackend.AmneziaParams{}
	}
	return p
}
