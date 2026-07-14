package snmp

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/reloadlife/wireguardd/internal/stats"
)

// Agent is a minimal SNMPv2c agent exposing interface/peer stats.
type Agent struct {
	listen    string
	community string
	baseOID   OID
	cache     *stats.Cache
	log       *slog.Logger

	mu   sync.Mutex
	conn *net.UDPConn
}

// NewAgent creates an SNMP agent.
func NewAgent(listen, community, enterpriseOID string, cache *stats.Cache, log *slog.Logger) *Agent {
	if community == "" {
		community = "public"
	}
	if enterpriseOID == "" {
		enterpriseOID = "1.3.6.1.4.1.66666.1"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Agent{
		listen:    listen,
		community: community,
		baseOID:   parseOID(enterpriseOID),
		cache:     cache,
		log:       log,
	}
}

// Start listens and serves SNMP until Close.
func (a *Agent) Start() error {
	addr, err := net.ResolveUDPAddr("udp", a.listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	a.log.Info("snmp agent listening", "addr", a.listen)
	go a.loop()
	return nil
}

// Close stops the agent.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

func (a *Agent) loop() {
	buf := make([]byte, 65535)
	for {
		a.mu.Lock()
		conn := a.conn
		a.mu.Unlock()
		if conn == nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// closed
			return
		}
		resp := a.handle(buf[:n])
		if resp != nil {
			_, _ = conn.WriteToUDP(resp, remote)
		}
	}
}

// Variable is a simple OID binding.
type Variable struct {
	OID   OID
	Type  byte // 0x02 integer, 0x04 octet, 0x41 counter32, 0x42 gauge32, 0x46 counter64
	Int   int64
	Str   string
}

func (a *Agent) snapshotVars() []Variable {
	ifaces, peers := a.cache.Snapshot()
	var vars []Variable
	// base.1.1.ifaceIndex.* interface table
	// base.1 = interfaces, base.2 = peers
	ifaceNames := make([]string, 0, len(ifaces))
	for n := range ifaces {
		ifaceNames = append(ifaceNames, n)
	}
	sort.Strings(ifaceNames)
	for i, name := range ifaceNames {
		idx := uint(i + 1)
		st := ifaces[name]
		up := int64(0)
		if st.Up {
			up = 1
		}
		vars = append(vars,
			Variable{OID: a.baseOID.Child(1, 1, idx), Type: 0x04, Str: name},
			Variable{OID: a.baseOID.Child(1, 2, idx), Type: 0x02, Int: up},
			Variable{OID: a.baseOID.Child(1, 3, idx), Type: 0x02, Int: int64(st.ListenPort)},
			Variable{OID: a.baseOID.Child(1, 4, idx), Type: 0x02, Int: int64(st.PeerCount)},
			Variable{OID: a.baseOID.Child(1, 5, idx), Type: 0x46, Int: st.RxBytes},
			Variable{OID: a.baseOID.Child(1, 6, idx), Type: 0x46, Int: st.TxBytes},
			Variable{OID: a.baseOID.Child(1, 7, idx), Type: 0x42, Int: int64(st.RxBps)},
			Variable{OID: a.baseOID.Child(1, 8, idx), Type: 0x42, Int: int64(st.TxBps)},
		)
	}
	// peers: sort keys
	keys := make([]string, 0, len(peers))
	for k := range peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		idx := uint(i + 1)
		p := peers[k]
		conn := int64(0)
		if p.Connected {
			conn = 1
		}
		susp := int64(0)
		if p.Suspended {
			susp = 1
		}
		hs := int64(0)
		if !p.LastHandshake.IsZero() {
			hs = p.LastHandshake.Unix()
		}
		vars = append(vars,
			Variable{OID: a.baseOID.Child(2, 1, idx), Type: 0x04, Str: p.Interface},
			Variable{OID: a.baseOID.Child(2, 2, idx), Type: 0x04, Str: p.PublicKey},
			Variable{OID: a.baseOID.Child(2, 3, idx), Type: 0x04, Str: p.Name},
			Variable{OID: a.baseOID.Child(2, 4, idx), Type: 0x04, Str: p.Endpoint},
			Variable{OID: a.baseOID.Child(2, 5, idx), Type: 0x02, Int: conn},
			Variable{OID: a.baseOID.Child(2, 6, idx), Type: 0x02, Int: susp},
			Variable{OID: a.baseOID.Child(2, 7, idx), Type: 0x02, Int: hs},
			Variable{OID: a.baseOID.Child(2, 8, idx), Type: 0x46, Int: p.RxBytes},
			Variable{OID: a.baseOID.Child(2, 9, idx), Type: 0x46, Int: p.TxBytes},
			Variable{OID: a.baseOID.Child(2, 10, idx), Type: 0x42, Int: int64(p.RxBps)},
			Variable{OID: a.baseOID.Child(2, 11, idx), Type: 0x42, Int: int64(p.TxBps)},
		)
	}
	sort.Slice(vars, func(i, j int) bool {
		return vars[i].OID.Compare(vars[j].OID) < 0
	})
	return vars
}

// handle parses a minimal SNMPv2c Get/GetNext and responds.
// This is intentionally simple and may not support all PDU types.
func (a *Agent) handle(req []byte) []byte {
	// Very small SNMP decode: find community string and request type loosely.
	// For robustness in production, use a full library; here we implement enough for snmpwalk basics.
	if len(req) < 20 {
		return nil
	}
	// Verify community appears as octet string
	if !containsCommunity(req, a.community) {
		return nil
	}
	vars := a.snapshotVars()
	// Build a simple response with sysDescr-like first var or all get-next from base
	// Detect GETNEXT (0xA1) vs GET (0xA0)
	isNext := false
	for _, b := range req {
		if b == 0xA1 {
			isNext = true
			break
		}
		if b == 0xA0 {
			break
		}
	}
	requested := extractOIDs(req)
	var bindings []Variable
	if len(requested) == 0 {
		if len(vars) > 0 {
			bindings = []Variable{vars[0]}
		}
	} else {
		for _, roid := range requested {
			if isNext {
				for _, v := range vars {
					if v.OID.Compare(roid) > 0 {
						bindings = append(bindings, v)
						break
					}
				}
			} else {
				for _, v := range vars {
					if v.OID.Equal(roid) {
						bindings = append(bindings, v)
						break
					}
				}
			}
		}
	}
	if len(bindings) == 0 {
		return nil
	}
	return encodeResponse(req, a.community, bindings)
}

func containsCommunity(req []byte, community string) bool {
	return len(community) > 0 && (stringIndex(req, []byte(community)) >= 0)
}

func stringIndex(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		ok := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func extractOIDs(req []byte) []OID {
	// Find sequences of 0x06 (OID tag) and parse
	var out []OID
	for i := 0; i < len(req); i++ {
		if req[i] != 0x06 || i+1 >= len(req) {
			continue
		}
		l := int(req[i+1])
		if l&0x80 != 0 || i+2+l > len(req) {
			continue
		}
		raw := req[i+2 : i+2+l]
		oid := decodeOID(raw)
		if len(oid) > 0 {
			out = append(out, oid)
		}
		i += 1 + l
	}
	return out
}

func decodeOID(raw []byte) OID {
	if len(raw) == 0 {
		return nil
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
	return out
}

func encodeOID(oid OID) []byte {
	if len(oid) < 2 {
		return []byte{0}
	}
	out := []byte{byte(oid[0]*40 + oid[1])}
	for _, n := range oid[2:] {
		out = append(out, encodeBase128(uint(n))...)
	}
	return out
}

func encodeBase128(n uint) []byte {
	if n == 0 {
		return []byte{0}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0x7f)}, tmp...)
		n >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

func encodeResponse(req []byte, community string, bindings []Variable) []byte {
	// Build SNMPv2c RESPONSE PDU manually (simplified).
	var varBind []byte
	for _, b := range bindings {
		oidBytes := encodeOID(b.OID)
		var value []byte
		switch b.Type {
		case 0x04:
			value = append([]byte{0x04, byte(len(b.Str))}, []byte(b.Str)...)
		case 0x02:
			value = encodeInteger(b.Int)
		case 0x42: // gauge32
			value = encodeGauge(b.Int)
		case 0x46: // counter64 as integer fallback for simplicity
			value = encodeInteger(b.Int)
		default:
			value = encodeInteger(b.Int)
		}
		vb := append([]byte{0x06, byte(len(oidBytes))}, oidBytes...)
		vb = append(vb, value...)
		varBind = append(varBind, wrap(0x30, vb)...)
	}
	// request-id copy: try to extract first integer after community
	reqID := []byte{0x02, 0x01, 0x01}
	errorStatus := []byte{0x02, 0x01, 0x00}
	errorIndex := []byte{0x02, 0x01, 0x00}
	pduBody := append(reqID, errorStatus...)
	pduBody = append(pduBody, errorIndex...)
	pduBody = append(pduBody, wrap(0x30, varBind)...)
	pdu := wrap(0xA2, pduBody) // GetResponse

	version := []byte{0x02, 0x01, 0x01} // v2c
	comm := append([]byte{0x04, byte(len(community))}, []byte(community)...)
	body := append(version, comm...)
	body = append(body, pdu...)
	_ = asn1.NullBytes
	_ = binary.BigEndian
	return wrap(0x30, body)
}

func wrap(tag byte, content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	// long form
	lb := []byte{tag, 0x82, byte(len(content) >> 8), byte(len(content))}
	return append(lb, content...)
}

func encodeInteger(v int64) []byte {
	// encode as ASN.1 INTEGER
	if v >= 0 && v < 128 {
		return []byte{0x02, 0x01, byte(v)}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	start := 0
	for start < 7 && buf[start] == 0 {
		start++
	}
	// if high bit set, keep leading zero for positive
	if buf[start]&0x80 != 0 && v >= 0 {
		start--
	}
	content := buf[start:]
	return append([]byte{0x02, byte(len(content))}, content...)
}

func encodeGauge(v int64) []byte {
	// Gauge32 application type 0x42
	if v < 0 {
		v = 0
	}
	if v < 256 {
		return []byte{0x42, 0x01, byte(v)}
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(v))
	return append([]byte{0x42, 0x04}, buf[:]...)
}

// String for debug
func (a *Agent) String() string {
	return fmt.Sprintf("snmp-agent(%s)", a.listen)
}
