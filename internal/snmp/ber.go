package snmp

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ASN.1 BER tags used by SNMPv2c.
const (
	tagBoolean        = 0x01
	tagInteger        = 0x02
	tagBitString      = 0x03
	tagOctetString    = 0x04
	tagNull           = 0x05
	tagOID            = 0x06
	tagSequence       = 0x30
	tagIPAddress      = 0x40 // application 0
	tagCounter32      = 0x41 // application 1
	tagGauge32        = 0x42 // application 2
	tagTimeTicks      = 0x43 // application 3
	tagOpaque         = 0x44 // application 4
	tagCounter64      = 0x46 // application 6
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
	tagGetRequest     = 0xA0
	tagGetNextRequest = 0xA1
	tagGetResponse    = 0xA2
	tagSetRequest     = 0xA3
	tagGetBulkRequest = 0xA5
	tagInformRequest  = 0xA6
	tagSNMPv2Trap     = 0xA7
	tagReport         = 0xA8
)

// Value is a typed SNMP value.
type Value struct {
	Type byte
	Int  int64  // Integer, Counter32, Gauge32, TimeTicks, Counter64 (low 63 bits ok for our counters)
	U64  uint64 // Counter64 full
	Str  string // OctetString / OID string display
	Raw  []byte // Opaque / IP raw
}

func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xff {
		return []byte{0x81, byte(n)}
	}
	if n <= 0xffff {
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

func wrapTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, 1+4+len(content))
	out = append(out, tag)
	out = append(out, encodeLength(len(content))...)
	out = append(out, content...)
	return out
}

func encodeInteger(v int64) []byte {
	// minimal two's-complement big-endian INTEGER
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(v))
	start := 0
	if v >= 0 {
		for start < 7 && buf[start] == 0 {
			start++
		}
		if buf[start]&0x80 != 0 {
			// positive value with high bit set needs a 0x00 prefix
			content := make([]byte, 0, 9-start)
			content = append(content, 0x00)
			content = append(content, buf[start:]...)
			return wrapTLV(tagInteger, content)
		}
	} else {
		for start < 7 && buf[start] == 0xff && buf[start+1]&0x80 != 0 {
			start++
		}
	}
	return wrapTLV(tagInteger, buf[start:])
}

func encodeUnsigned32(tag byte, v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	start := 0
	for start < 3 && buf[start] == 0 {
		start++
	}
	// unsigned types: if high bit set, prepend 0x00 (BER integer rules used by some stacks)
	if buf[start]&0x80 != 0 {
		content := append([]byte{0x00}, buf[start:]...)
		return wrapTLV(tag, content)
	}
	return wrapTLV(tag, buf[start:])
}

func encodeCounter64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	start := 0
	for start < 7 && buf[start] == 0 {
		start++
	}
	if buf[start]&0x80 != 0 {
		content := append([]byte{0x00}, buf[start:]...)
		return wrapTLV(tagCounter64, content)
	}
	return wrapTLV(tagCounter64, buf[start:])
}

func encodeOctetString(s string) []byte {
	return wrapTLV(tagOctetString, []byte(s))
}

func encodeNull() []byte {
	return []byte{tagNull, 0x00}
}

func encodeOID(oid OID) []byte {
	if len(oid) < 2 {
		return wrapTLV(tagOID, []byte{0})
	}
	// first byte = 40*first + second (encode best-effort even if OID is non-standard)
	first := byte(oid[0]*40 + oid[1])
	content := []byte{first}
	for _, n := range oid[2:] {
		content = append(content, encodeBase128(n)...)
	}
	return wrapTLV(tagOID, content)
}

func encodeBase128(n uint) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var stack []byte
	for n > 0 {
		stack = append(stack, byte(n&0x7f))
		n >>= 7
	}
	// reverse with high bits
	out := make([]byte, len(stack))
	for i := 0; i < len(stack); i++ {
		b := stack[len(stack)-1-i]
		if i < len(stack)-1 {
			b |= 0x80
		}
		out[i] = b
	}
	return out
}

func encodeValue(v Value) []byte {
	switch v.Type {
	case tagInteger:
		return encodeInteger(v.Int)
	case tagOctetString:
		return encodeOctetString(v.Str)
	case tagNull:
		return encodeNull()
	case tagOID:
		return encodeOID(parseOID(v.Str))
	case tagCounter32:
		return encodeUnsigned32(tagCounter32, uint32(v.Int))
	case tagGauge32:
		return encodeUnsigned32(tagGauge32, uint32(v.Int))
	case tagTimeTicks:
		return encodeUnsigned32(tagTimeTicks, uint32(v.Int))
	case tagCounter64:
		if v.U64 != 0 || v.Int == 0 {
			return encodeCounter64(v.U64)
		}
		if v.Int < 0 {
			return encodeCounter64(0)
		}
		return encodeCounter64(uint64(v.Int))
	case tagIPAddress:
		if len(v.Raw) == 4 {
			return wrapTLV(tagIPAddress, v.Raw)
		}
		return wrapTLV(tagIPAddress, []byte{0, 0, 0, 0})
	case tagNoSuchObject:
		return []byte{tagNoSuchObject, 0x00}
	case tagNoSuchInstance:
		return []byte{tagNoSuchInstance, 0x00}
	case tagEndOfMibView:
		return []byte{tagEndOfMibView, 0x00}
	default:
		return encodeInteger(v.Int)
	}
}

// --- decode ---

type reader struct {
	b []byte
	i int
}

func (r *reader) remaining() int { return len(r.b) - r.i }

func (r *reader) readByte() (byte, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("eof")
	}
	b := r.b[r.i]
	r.i++
	return b, nil
}

func (r *reader) readLength() (int, error) {
	b, err := r.readByte()
	if err != nil {
		return 0, err
	}
	if b < 0x80 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("invalid length form")
	}
	var l int
	for i := 0; i < n; i++ {
		bb, err := r.readByte()
		if err != nil {
			return 0, err
		}
		l = (l << 8) | int(bb)
	}
	return l, nil
}

func (r *reader) readTLV() (tag byte, content []byte, err error) {
	tag, err = r.readByte()
	if err != nil {
		return 0, nil, err
	}
	l, err := r.readLength()
	if err != nil {
		return 0, nil, err
	}
	if r.remaining() < l {
		return 0, nil, fmt.Errorf("truncated content")
	}
	content = r.b[r.i : r.i+l]
	r.i += l
	return tag, content, nil
}

func decodeOIDContent(raw []byte) (OID, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty oid")
	}
	out := OID{uint(raw[0] / 40), uint(raw[0] % 40)}
	var v uint
	for i := 1; i < len(raw); i++ {
		v = (v << 7) | uint(raw[i]&0x7f)
		if raw[i]&0x80 == 0 {
			out = append(out, v)
			v = 0
		}
	}
	return out, nil
}

func decodeIntegerContent(raw []byte) (int64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("empty integer")
	}
	if len(raw) > 8 {
		return 0, fmt.Errorf("integer too large")
	}
	// sign extend
	var v int64
	if raw[0]&0x80 != 0 {
		v = -1
	}
	for _, b := range raw {
		v = (v << 8) | int64(b)
	}
	return v, nil
}

func decodeUnsignedContent(raw []byte) (uint64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("empty unsigned")
	}
	// skip leading 0x00 padding
	i := 0
	if len(raw) > 1 && raw[0] == 0 {
		i = 1
	}
	var v uint64
	for ; i < len(raw); i++ {
		v = (v << 8) | uint64(raw[i])
	}
	return v, nil
}

func decodeValue(tag byte, content []byte) (Value, error) {
	switch tag {
	case tagInteger:
		n, err := decodeIntegerContent(content)
		return Value{Type: tagInteger, Int: n}, err
	case tagOctetString:
		return Value{Type: tagOctetString, Str: string(content)}, nil
	case tagNull:
		return Value{Type: tagNull}, nil
	case tagOID:
		oid, err := decodeOIDContent(content)
		return Value{Type: tagOID, Str: oid.String()}, err
	case tagCounter32:
		u, err := decodeUnsignedContent(content)
		return Value{Type: tagCounter32, Int: int64(u & math.MaxUint32)}, err
	case tagGauge32:
		u, err := decodeUnsignedContent(content)
		return Value{Type: tagGauge32, Int: int64(u & math.MaxUint32)}, err
	case tagTimeTicks:
		u, err := decodeUnsignedContent(content)
		return Value{Type: tagTimeTicks, Int: int64(u & math.MaxUint32)}, err
	case tagCounter64:
		u, err := decodeUnsignedContent(content)
		return Value{Type: tagCounter64, U64: u, Int: int64(u)}, err
	case tagIPAddress:
		return Value{Type: tagIPAddress, Raw: append([]byte(nil), content...)}, nil
	case tagNoSuchObject:
		return Value{Type: tagNoSuchObject}, nil
	case tagNoSuchInstance:
		return Value{Type: tagNoSuchInstance}, nil
	case tagEndOfMibView:
		return Value{Type: tagEndOfMibView}, nil
	default:
		return Value{Type: tag, Raw: append([]byte(nil), content...)}, nil
	}
}
