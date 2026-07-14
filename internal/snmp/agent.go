package snmp

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/reloadlife/wireguardd/internal/stats"
)

// Agent is a full SNMPv2c agent (GET, GETNEXT, GETBULK; SET → notWritable).
type Agent struct {
	listen    string
	community string
	baseOID   OID
	cache     *stats.Cache
	log       *slog.Logger
	started   time.Time
	readOnly  bool

	mu   sync.Mutex
	conn *net.UDPConn
}

// Options configures the agent.
type Options struct {
	Listen        string
	Community     string
	EnterpriseOID string
	ReadOnly      bool // default true
}

// NewAgent creates an SNMPv2c agent.
func NewAgent(listen, community, enterpriseOID string, cache *stats.Cache, log *slog.Logger) *Agent {
	return NewAgentOpts(Options{
		Listen:        listen,
		Community:     community,
		EnterpriseOID: enterpriseOID,
		ReadOnly:      true,
	}, cache, log)
}

// NewAgentOpts creates an agent with full options.
func NewAgentOpts(opts Options, cache *stats.Cache, log *slog.Logger) *Agent {
	if opts.Community == "" {
		opts.Community = "public"
	}
	if opts.EnterpriseOID == "" {
		opts.EnterpriseOID = "1.3.6.1.4.1.66666.1"
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:1161"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Agent{
		listen:    opts.Listen,
		community: opts.Community,
		baseOID:   parseOID(opts.EnterpriseOID),
		cache:     cache,
		log:       log,
		started:   time.Now(),
		readOnly:  opts.ReadOnly,
	}
}

// Start listens and serves until Close.
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
	a.log.Info("snmp agent listening", "addr", conn.LocalAddr().String(), "community", a.community, "version", "2c")
	go a.loop()
	return nil
}

// Addr returns the bound address (after Start).
func (a *Agent) Addr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return nil
	}
	return a.conn.LocalAddr()
}

// Close stops the agent.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil {
		err := a.conn.Close()
		a.conn = nil
		return err
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
			return
		}
		resp := a.HandlePacket(buf[:n])
		if len(resp) > 0 {
			_, _ = conn.WriteToUDP(resp, remote)
		}
	}
}

// HandlePacket processes one SNMPv2c request and returns a response datagram (or nil).
// Exported for unit tests.
func (a *Agent) HandlePacket(req []byte) []byte {
	msg, err := decodeMessage(req)
	if err != nil {
		a.log.Debug("snmp decode error", "err", err)
		return nil
	}
	// only v2c (version=1) and v1 (version=0) community messages
	if msg.Version != 0 && msg.Version != 1 {
		return nil
	}
	if msg.Community != a.community {
		a.log.Debug("snmp bad community")
		return nil
	}

	mib := BuildMIB(a.baseOID, a.cache, a.started)
	var outPDU PDU
	outPDU.RequestID = msg.PDU.RequestID
	outPDU.Type = PDUResponse

	switch msg.PDU.Type {
	case PDUGet:
		outPDU.Bindings = a.doGet(mib, msg.PDU.Bindings)
	case PDUGetNext:
		outPDU.Bindings = a.doGetNext(mib, msg.PDU.Bindings)
	case PDUGetBulk:
		outPDU.Bindings = a.doGetBulk(mib, msg.PDU)
	case PDUSet:
		outPDU.ErrorStatus = ErrNotWritable
		outPDU.ErrorIndex = 1
		// echo bindings with no change
		outPDU.Bindings = make([]VarBind, len(msg.PDU.Bindings))
		for i, b := range msg.PDU.Bindings {
			outPDU.Bindings[i] = VarBind{Name: b.Name, Value: b.Value}
		}
		if len(outPDU.Bindings) == 0 {
			outPDU.ErrorIndex = 0
		}
	default:
		// unsupported → genErr
		outPDU.ErrorStatus = ErrGenErr
		outPDU.Bindings = msg.PDU.Bindings
	}

	// cap response size roughly (UDP safety)
	resp := encodeMessage(&Message{
		Version:   msg.Version,
		Community: a.community,
		PDU:       outPDU,
	})
	if len(resp) > 64000 {
		outPDU.ErrorStatus = ErrTooBig
		outPDU.ErrorIndex = 0
		outPDU.Bindings = nil
		resp = encodeMessage(&Message{Version: msg.Version, Community: a.community, PDU: outPDU})
	}
	return resp
}

func (a *Agent) doGet(mib *MIB, req []VarBind) []VarBind {
	out := make([]VarBind, 0, len(req))
	for _, b := range req {
		if v, ok := mib.Get(b.Name); ok {
			out = append(out, VarBind{Name: v.OID, Value: v.Value})
			continue
		}
		// noSuchObject if nothing under prefix, else noSuchInstance
		if a.hasPrefix(mib, b.Name) {
			out = append(out, VarBind{Name: b.Name, Value: Value{Type: tagNoSuchInstance}})
		} else {
			out = append(out, VarBind{Name: b.Name, Value: Value{Type: tagNoSuchObject}})
		}
	}
	return out
}

func (a *Agent) hasPrefix(mib *MIB, oid OID) bool {
	for _, v := range mib.vars {
		if oid.IsPrefix(v.OID) {
			return true
		}
	}
	return false
}

func (a *Agent) doGetNext(mib *MIB, req []VarBind) []VarBind {
	out := make([]VarBind, 0, len(req))
	for _, b := range req {
		if v, ok := mib.GetNext(b.Name); ok {
			out = append(out, VarBind{Name: v.OID, Value: v.Value})
		} else {
			out = append(out, VarBind{Name: b.Name, Value: Value{Type: tagEndOfMibView}})
		}
	}
	return out
}

func (a *Agent) doGetBulk(mib *MIB, pdu PDU) []VarBind {
	nonRep := pdu.NonRepeaters
	maxRep := pdu.MaxRepetitions
	if nonRep < 0 {
		nonRep = 0
	}
	if maxRep < 0 {
		maxRep = 0
	}
	if maxRep > 100 {
		maxRep = 100 // safety
	}
	if nonRep > len(pdu.Bindings) {
		nonRep = len(pdu.Bindings)
	}

	var out []VarBind
	// non-repeaters: one GetNext each
	for i := 0; i < nonRep; i++ {
		b := pdu.Bindings[i]
		if v, ok := mib.GetNext(b.Name); ok {
			out = append(out, VarBind{Name: v.OID, Value: v.Value})
		} else {
			out = append(out, VarBind{Name: b.Name, Value: Value{Type: tagEndOfMibView}})
		}
	}
	// repeaters
	reps := pdu.Bindings[nonRep:]
	if len(reps) == 0 || maxRep == 0 {
		return out
	}
	cursors := make([]OID, len(reps))
	for i, b := range reps {
		cursors[i] = b.Name
	}
	for r := 0; r < maxRep; r++ {
		allEnd := true
		for i := range reps {
			if v, ok := mib.GetNext(cursors[i]); ok {
				out = append(out, VarBind{Name: v.OID, Value: v.Value})
				cursors[i] = v.OID
				allEnd = false
			} else {
				out = append(out, VarBind{Name: cursors[i], Value: Value{Type: tagEndOfMibView}})
			}
		}
		if allEnd {
			break
		}
	}
	return out
}

// String debug.
func (a *Agent) String() string {
	return fmt.Sprintf("snmp-agent(v2c,%s)", a.listen)
}

// SnapshotVars builds a debug list of current leaves (tests/compat).
func (a *Agent) SnapshotVars() []Variable {
	return BuildMIB(a.baseOID, a.cache, a.started).vars
}
