package snmp

import (
	"strconv"
	"strings"
)

// OID is a numeric OID path.
type OID []uint

func parseOID(s string) OID {
	s = strings.TrimPrefix(s, ".")
	parts := strings.Split(s, ".")
	out := make(OID, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		out = append(out, uint(n))
	}
	return out
}

func (o OID) String() string {
	var b strings.Builder
	for i, n := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

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
