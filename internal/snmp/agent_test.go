package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/stats"
)

func TestOIDCompare(t *testing.T) {
	a := parseOID("1.3.6.1")
	b := parseOID("1.3.6.1.4")
	require.Equal(t, -1, a.Compare(b))
	require.True(t, a.IsPrefix(b))
	require.Equal(t, "1.3.6.1.4", a.Child(4).String())
}

func TestBERRoundTripIntegerOID(t *testing.T) {
	raw := encodeInteger(51820)
	r := &reader{b: raw}
	tag, content, err := r.readTLV()
	require.NoError(t, err)
	require.Equal(t, byte(tagInteger), tag)
	n, err := decodeIntegerContent(content)
	require.NoError(t, err)
	require.Equal(t, int64(51820), n)

	oid := parseOID("1.3.6.1.4.1.66666.1.2.1.2.1")
	enc := encodeOID(oid)
	r = &reader{b: enc}
	tag, content, err = r.readTLV()
	require.NoError(t, err)
	require.Equal(t, byte(tagOID), tag)
	got, err := decodeOIDContent(content)
	require.NoError(t, err)
	require.True(t, oid.Equal(got))
}

func TestCounter64Encode(t *testing.T) {
	raw := encodeCounter64(10)
	r := &reader{b: raw}
	tag, content, err := r.readTLV()
	require.NoError(t, err)
	require.Equal(t, byte(tagCounter64), tag)
	u, err := decodeUnsignedContent(content)
	require.NoError(t, err)
	require.Equal(t, uint64(10), u)
}

func testCache() *stats.Cache {
	cache := stats.NewCache()
	cache.SetInterface(stats.IfaceStats{
		Name: "wg0", PublicKey: "IfPubKey==", Up: true, ListenPort: 51820,
		PeerCount: 1, RxBytes: 1000, TxBytes: 2000, RxBps: 100, TxBps: 200,
	})
	cache.SetPeer(stats.PeerStats{
		Interface: "wg0", PublicKey: "PeerPubKey==", Name: "alice",
		Endpoint: "203.0.113.1:51820", Connected: true, RxBytes: 500, TxBytes: 600,
		RxBps: 50, TxBps: 60, TrafficLimitBytes: 1e9, BandwidthRxBps: 1e6, BandwidthTxBps: 2e6,
	})
	return cache
}

func TestGetAndGetNext(t *testing.T) {
	cache := testCache()
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", cache, nil)
	mib := BuildMIB(a.baseOID, cache, time.Now().Add(-time.Minute))
	require.Greater(t, mib.Len(), 10)

	// sysDescr
	sysDescr := parseOID("1.3.6.1.2.1.1.1.0")
	v, ok := mib.Get(sysDescr)
	require.True(t, ok)
	require.Contains(t, v.Value.Str, "wireguardd")

	// getnext from sysDescr → sysObjectID
	n, ok := mib.GetNext(sysDescr)
	require.True(t, ok)
	require.Equal(t, "1.3.6.1.2.1.1.2.0", n.OID.String())

	// interface name
	ifName := parseOID("1.3.6.1.4.1.66666.1.2.1.2.1")
	v, ok = mib.Get(ifName)
	require.True(t, ok)
	require.Equal(t, "wg0", v.Value.Str)

	// peer name
	peerName := parseOID("1.3.6.1.4.1.66666.1.3.1.4.1")
	v, ok = mib.Get(peerName)
	require.True(t, ok)
	require.Equal(t, "alice", v.Value.Str)
}

func TestHandleGet(t *testing.T) {
	cache := testCache()
	a := NewAgent("127.0.0.1:0", "secret", "1.3.6.1.4.1.66666.1", cache, nil)

	req := encodeMessage(&Message{
		Version:   1,
		Community: "secret",
		PDU: PDU{
			Type:      PDUGet,
			RequestID: 42,
			Bindings: []VarBind{
				{Name: parseOID("1.3.6.1.2.1.1.1.0"), Value: Value{Type: tagNull}},
				{Name: parseOID("1.3.6.1.4.1.66666.1.2.1.2.1"), Value: Value{Type: tagNull}},
			},
		},
	})
	resp := a.HandlePacket(req)
	require.NotEmpty(t, resp)

	msg, err := decodeMessage(resp)
	require.NoError(t, err)
	require.Equal(t, 1, msg.Version)
	require.Equal(t, "secret", msg.Community)
	require.Equal(t, byte(PDUResponse), msg.PDU.Type)
	require.Equal(t, int32(42), msg.PDU.RequestID)
	require.Equal(t, ErrNoError, msg.PDU.ErrorStatus)
	require.Len(t, msg.PDU.Bindings, 2)
	require.Contains(t, msg.PDU.Bindings[0].Value.Str, "wireguardd")
	require.Equal(t, "wg0", msg.PDU.Bindings[1].Value.Str)
}

func TestHandleBadCommunity(t *testing.T) {
	a := NewAgent("127.0.0.1:0", "secret", "1.3.6.1.4.1.66666.1", testCache(), nil)
	req := encodeMessage(&Message{
		Version: 1, Community: "wrong",
		PDU: PDU{Type: PDUGet, RequestID: 1, Bindings: []VarBind{
			{Name: parseOID("1.3.6.1.2.1.1.1.0"), Value: Value{Type: tagNull}},
		}},
	})
	require.Nil(t, a.HandlePacket(req))
}

func TestHandleGetNextWalk(t *testing.T) {
	cache := testCache()
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", cache, nil)
	cursor := parseOID("1.3.6.1.4.1.66666.1")
	var walked []string
	for i := 0; i < 200; i++ {
		req := encodeMessage(&Message{
			Version: 1, Community: "public",
			PDU: PDU{Type: PDUGetNext, RequestID: int32(i), Bindings: []VarBind{
				{Name: cursor, Value: Value{Type: tagNull}},
			}},
		})
		resp := a.HandlePacket(req)
		require.NotEmpty(t, resp)
		msg, err := decodeMessage(resp)
		require.NoError(t, err)
		require.Len(t, msg.PDU.Bindings, 1)
		b := msg.PDU.Bindings[0]
		if b.Value.Type == tagEndOfMibView {
			break
		}
		// stay under enterprise tree for this test loop bound
		if !parseOID("1.3.6.1.4.1.66666.1").IsPrefix(b.Name) && b.Name.Compare(parseOID("1.3.6.1.4.1.66666.1")) > 0 {
			// may walk into nothing after base — stop when past our base children
			if b.Name.Compare(parseOID("1.3.6.1.4.1.66666.2")) >= 0 {
				break
			}
		}
		walked = append(walked, b.Name.String())
		cursor = b.Name
	}
	require.NotEmpty(t, walked)
	// should include interface + peer leaves
	joined := ""
	for _, s := range walked {
		joined += s + "\n"
	}
	require.Contains(t, joined, "1.3.6.1.4.1.66666.1.2.1")
	require.Contains(t, joined, "1.3.6.1.4.1.66666.1.3.1")
}

func TestHandleGetBulk(t *testing.T) {
	cache := testCache()
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", cache, nil)
	req := encodeMessage(&Message{
		Version: 1, Community: "public",
		PDU: PDU{
			Type:           PDUGetBulk,
			RequestID:      7,
			IsBulk:         true,
			NonRepeaters:   1,
			MaxRepetitions: 5,
			Bindings: []VarBind{
				{Name: parseOID("1.3.6.1.2.1.1.1.0"), Value: Value{Type: tagNull}}, // non-rep
				{Name: parseOID("1.3.6.1.4.1.66666.1.2.1.2"), Value: Value{Type: tagNull}},
			},
		},
	})
	resp := a.HandlePacket(req)
	require.NotEmpty(t, resp)
	msg, err := decodeMessage(resp)
	require.NoError(t, err)
	require.Equal(t, int32(7), msg.PDU.RequestID)
	require.GreaterOrEqual(t, len(msg.PDU.Bindings), 2)
	// first binding is getnext of sysDescr
	require.Equal(t, "1.3.6.1.2.1.1.2.0", msg.PDU.Bindings[0].Name.String())
}

func TestHandleSetReadOnly(t *testing.T) {
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", testCache(), nil)
	req := encodeMessage(&Message{
		Version: 1, Community: "public",
		PDU: PDU{
			Type: PDUSet, RequestID: 9,
			Bindings: []VarBind{{
				Name:  parseOID("1.3.6.1.2.1.1.4.0"),
				Value: Value{Type: tagOctetString, Str: "hacked"},
			}},
		},
	})
	resp := a.HandlePacket(req)
	msg, err := decodeMessage(resp)
	require.NoError(t, err)
	require.Equal(t, ErrNotWritable, msg.PDU.ErrorStatus)
}

func TestNoSuchObject(t *testing.T) {
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", testCache(), nil)
	req := encodeMessage(&Message{
		Version: 1, Community: "public",
		PDU: PDU{Type: PDUGet, RequestID: 1, Bindings: []VarBind{
			{Name: parseOID("1.2.3.4.5.6"), Value: Value{Type: tagNull}},
		}},
	})
	resp := a.HandlePacket(req)
	msg, err := decodeMessage(resp)
	require.NoError(t, err)
	require.Equal(t, byte(tagNoSuchObject), msg.PDU.Bindings[0].Value.Type)
}

func TestLiveUDPAgent(t *testing.T) {
	cache := testCache()
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", cache, nil)
	require.NoError(t, a.Start())
	defer a.Close()
	addr := a.Addr().(*net.UDPAddr)

	req := encodeMessage(&Message{
		Version: 1, Community: "public",
		PDU: PDU{Type: PDUGet, RequestID: 99, Bindings: []VarBind{
			{Name: parseOID("1.3.6.1.4.1.66666.1.1.1.0"), Value: Value{Type: tagNull}}, // iface count
		}},
	})
	conn, err := net.DialUDP("udp", nil, addr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write(req)
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	msg, err := decodeMessage(buf[:n])
	require.NoError(t, err)
	require.Equal(t, int32(99), msg.PDU.RequestID)
	require.Equal(t, int64(1), msg.PDU.Bindings[0].Value.Int) // 1 interface
}

func TestSnapshotVarsCompat(t *testing.T) {
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", testCache(), nil)
	vars := a.SnapshotVars()
	require.NotEmpty(t, vars)
}
