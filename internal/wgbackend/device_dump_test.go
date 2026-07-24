package wgbackend

import (
	"testing"
	"time"
)

func TestParseShowDump_InterfaceAndPeer(t *testing.T) {
	// Realistic awg/wg dump (tab-separated). Handshake = 1700000000.
	raw := "YPrivKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\tYPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t51830\toff\n" +
		"PeerPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t1.2.3.4:51820\t10.8.0.5/32\t1700000000\t12345\t67890\t25\n"

	dev, err := parseShowDump("wg-owire-awg", raw)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Name != "wg-owire-awg" {
		t.Fatalf("name %q", dev.Name)
	}
	if dev.ListenPort != 51830 {
		t.Fatalf("port %d", dev.ListenPort)
	}
	if dev.PublicKey == "" {
		t.Fatal("expected public key")
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("peers %d", len(dev.Peers))
	}
	p := dev.Peers[0]
	if p.PublicKey != "PeerPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("peer pub %q", p.PublicKey)
	}
	if p.Endpoint != "1.2.3.4:51820" {
		t.Fatalf("endpoint %q", p.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.8.0.5/32" {
		t.Fatalf("allowed %v", p.AllowedIPs)
	}
	if p.ReceiveBytes != 12345 || p.TransmitBytes != 67890 {
		t.Fatalf("rx/tx %d/%d", p.ReceiveBytes, p.TransmitBytes)
	}
	if p.PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("ka %v", p.PersistentKeepaliveInterval)
	}
	wantHS := time.Unix(1700000000, 0)
	if !p.LastHandshakeTime.Equal(wantHS) {
		t.Fatalf("handshake %v want %v", p.LastHandshakeTime, wantHS)
	}
}

func TestParseShowDump_ZeroHandshakeNeverConnected(t *testing.T) {
	raw := "priv\tpub\t51820\toff\n" +
		"peerpub\t(none)\t(none)\t10.8.0.6/32\t0\t0\t0\toff\n"
	dev, err := parseShowDump("wg0", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("peers %d", len(dev.Peers))
	}
	if !dev.Peers[0].LastHandshakeTime.IsZero() {
		t.Fatalf("expected zero handshake, got %v", dev.Peers[0].LastHandshakeTime)
	}
	if dev.Peers[0].Endpoint != "" {
		t.Fatalf("endpoint should be empty, got %q", dev.Peers[0].Endpoint)
	}
}

func TestParseShowDump_MultipleAllowedIPs(t *testing.T) {
	raw := "priv\tpub\t51820\t0\n" +
		"peerpub\tpsk\t9.9.9.9:1\t10.8.0.7/32,fd00::7/128\t1700000001\t1\t2\t15\n"
	dev, err := parseShowDump("wg0", raw)
	if err != nil {
		t.Fatal(err)
	}
	p := dev.Peers[0]
	if len(p.AllowedIPs) != 2 {
		t.Fatalf("allowed %v", p.AllowedIPs)
	}
	if p.PresharedKey != "psk" {
		t.Fatalf("psk %q", p.PresharedKey)
	}
}

func TestParseShowDump_Empty(t *testing.T) {
	if _, err := parseShowDump("x", ""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := parseShowDump("x", "only-three\tfields\there"); err == nil {
		t.Fatal("expected malformed header error")
	}
}

func TestParseShowDump_NoPeers(t *testing.T) {
	raw := "priv\tpub\t51820\toff\n"
	dev, err := parseShowDump("wg0", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Peers) != 0 {
		t.Fatalf("peers %d", len(dev.Peers))
	}
}
