package snmp

import (
	"fmt"
)

// PDU types.
const (
	PDUGet      = tagGetRequest
	PDUGetNext  = tagGetNextRequest
	PDUResponse = tagGetResponse
	PDUSet      = tagSetRequest
	PDUGetBulk  = tagGetBulkRequest
)

// Error statuses (SNMPv2).
const (
	ErrNoError             = 0
	ErrTooBig              = 1
	ErrNoSuchName          = 2
	ErrBadValue            = 3
	ErrReadOnly            = 4
	ErrGenErr              = 5
	ErrNoAccess            = 6
	ErrWrongType           = 7
	ErrWrongLength         = 8
	ErrWrongEncoding       = 9
	ErrWrongValue          = 10
	ErrNoCreation          = 11
	ErrInconsistentValue   = 12
	ErrResourceUnavailable = 13
	ErrCommitFailed        = 14
	ErrUndoFailed          = 15
	ErrAuthorizationError  = 16
	ErrNotWritable         = 17
	ErrInconsistentName    = 18
)

// VarBind is a name/value pair.
type VarBind struct {
	Name  OID
	Value Value
}

// PDU is an SNMP protocol data unit.
type PDU struct {
	Type           byte
	RequestID      int32
	ErrorStatus    int // or NonRepeaters for GetBulk
	ErrorIndex     int // or MaxRepetitions for GetBulk
	NonRepeaters   int
	MaxRepetitions int
	IsBulk         bool
	Bindings       []VarBind
}

// Message is an SNMPv2c message.
type Message struct {
	Version   int // 1 = v2c
	Community string
	PDU       PDU
}

func decodeMessage(raw []byte) (*Message, error) {
	r := &reader{b: raw}
	tag, content, err := r.readTLV()
	if err != nil {
		return nil, err
	}
	if tag != tagSequence {
		return nil, fmt.Errorf("expected SEQUENCE, got 0x%02x", tag)
	}
	inner := &reader{b: content}

	// version
	t, c, err := inner.readTLV()
	if err != nil {
		return nil, err
	}
	if t != tagInteger {
		return nil, fmt.Errorf("version not integer")
	}
	ver, err := decodeIntegerContent(c)
	if err != nil {
		return nil, err
	}

	// community
	t, c, err = inner.readTLV()
	if err != nil {
		return nil, err
	}
	if t != tagOctetString {
		return nil, fmt.Errorf("community not octet string")
	}
	community := string(c)

	// PDU
	t, c, err = inner.readTLV()
	if err != nil {
		return nil, err
	}
	pdu, err := decodePDU(t, c)
	if err != nil {
		return nil, err
	}
	return &Message{Version: int(ver), Community: community, PDU: *pdu}, nil
}

func decodePDU(tag byte, content []byte) (*PDU, error) {
	p := &PDU{Type: tag, IsBulk: tag == PDUGetBulk}
	r := &reader{b: content}

	// request-id
	t, c, err := r.readTLV()
	if err != nil {
		return nil, err
	}
	id, err := decodeIntegerContent(c)
	if err != nil {
		return nil, err
	}
	p.RequestID = int32(id)
	if t != tagInteger {
		return nil, fmt.Errorf("request-id not integer")
	}

	// error-status / non-repeaters
	_, c, err = r.readTLV()
	if err != nil {
		return nil, err
	}
	n1, err := decodeIntegerContent(c)
	if err != nil {
		return nil, err
	}
	// error-index / max-repetitions
	_, c, err = r.readTLV()
	if err != nil {
		return nil, err
	}
	n2, err := decodeIntegerContent(c)
	if err != nil {
		return nil, err
	}
	if p.IsBulk {
		p.NonRepeaters = int(n1)
		p.MaxRepetitions = int(n2)
	} else {
		p.ErrorStatus = int(n1)
		p.ErrorIndex = int(n2)
	}
	_ = t

	// varbind list
	t, c, err = r.readTLV()
	if err != nil {
		return nil, err
	}
	if t != tagSequence {
		return nil, fmt.Errorf("varbind list not SEQUENCE")
	}
	vr := &reader{b: c}
	for vr.remaining() > 0 {
		tt, cc, err := vr.readTLV()
		if err != nil {
			return nil, err
		}
		if tt != tagSequence {
			return nil, fmt.Errorf("varbind not SEQUENCE")
		}
		vb, err := decodeVarBind(cc)
		if err != nil {
			return nil, err
		}
		p.Bindings = append(p.Bindings, vb)
	}
	return p, nil
}

func decodeVarBind(content []byte) (VarBind, error) {
	r := &reader{b: content}
	t, c, err := r.readTLV()
	if err != nil {
		return VarBind{}, err
	}
	if t != tagOID {
		return VarBind{}, fmt.Errorf("varbind name not OID")
	}
	oid, err := decodeOIDContent(c)
	if err != nil {
		return VarBind{}, err
	}
	t, c, err = r.readTLV()
	if err != nil {
		return VarBind{}, err
	}
	val, err := decodeValue(t, c)
	if err != nil {
		return VarBind{}, err
	}
	return VarBind{Name: oid, Value: val}, nil
}

func encodeMessage(m *Message) []byte {
	ver := encodeInteger(int64(m.Version))
	comm := encodeOctetString(m.Community)
	pdu := encodePDU(&m.PDU)
	body := append(ver, comm...)
	body = append(body, pdu...)
	return wrapTLV(tagSequence, body)
}

func encodePDU(p *PDU) []byte {
	reqID := encodeInteger(int64(p.RequestID))
	var e1, e2 []byte
	if p.IsBulk && p.Type == PDUGetBulk {
		e1 = encodeInteger(int64(p.NonRepeaters))
		e2 = encodeInteger(int64(p.MaxRepetitions))
	} else {
		e1 = encodeInteger(int64(p.ErrorStatus))
		e2 = encodeInteger(int64(p.ErrorIndex))
	}
	var vbs []byte
	for _, b := range p.Bindings {
		vbs = append(vbs, encodeVarBind(b)...)
	}
	vbList := wrapTLV(tagSequence, vbs)
	content := append(reqID, e1...)
	content = append(content, e2...)
	content = append(content, vbList...)
	tag := p.Type
	if tag == 0 {
		tag = PDUResponse
	}
	return wrapTLV(tag, content)
}

func encodeVarBind(b VarBind) []byte {
	name := encodeOID(b.Name)
	val := encodeValue(b.Value)
	return wrapTLV(tagSequence, append(name, val...))
}
