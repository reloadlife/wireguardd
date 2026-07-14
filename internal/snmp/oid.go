package snmp

import (
	"strconv"
	"strings"
)

// OID is a numeric OID path.
type OID []uint

// ParseOID parses a dotted OID string (with optional leading dot).
func ParseOID(s string) OID { return parseOID(s) }

func parseOID(s string) OID {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make(OID, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			continue
		}
		out = append(out, uint(n))
	}
	return out
}

func (o OID) String() string {
	if len(o) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

// Equal reports exact equality.
func (o OID) Equal(other OID) bool {
	if len(o) != len(other) {
		return false
	}
	for i := range o {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}

// Child appends sub-identifiers.
func (o OID) Child(extra ...uint) OID {
	out := make(OID, len(o)+len(extra))
	copy(out, o)
	copy(out[len(o):], extra)
	return out
}

// Compare returns -1, 0, 1.
func (o OID) Compare(other OID) int {
	n := len(o)
	if len(other) < n {
		n = len(other)
	}
	for i := 0; i < n; i++ {
		if o[i] < other[i] {
			return -1
		}
		if o[i] > other[i] {
			return 1
		}
	}
	if len(o) < len(other) {
		return -1
	}
	if len(o) > len(other) {
		return 1
	}
	return 0
}

// IsPrefix reports whether o is a prefix of other.
func (o OID) IsPrefix(other OID) bool {
	if len(o) > len(other) {
		return false
	}
	for i := range o {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}
