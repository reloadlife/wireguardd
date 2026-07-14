package wgutil

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// NormalizeKey trims and validates a standard base64 WireGuard key.
func NormalizeKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty key")
	}
	// Accept URL-safe base64 by converting.
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid key encoding: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("invalid key length %d", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ShortKey returns a short display form of a public key.
func ShortKey(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

// PathEscapeKey encodes a key for use in URL paths (URL-safe base64).
func PathEscapeKey(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

// PathUnescapeKey reverses PathEscapeKey.
func PathUnescapeKey(s string) (string, error) {
	return NormalizeKey(s)
}
