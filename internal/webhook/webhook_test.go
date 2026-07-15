package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/webhook"
)

func TestDispatcherDeliversWithHMAC(t *testing.T) {
	var got atomic.Int32
	var sig string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = b
		sig = r.Header.Get("X-Webhook-Signature")
		require.Equal(t, "wireguardd", r.Header.Get("X-Agent"))
		got.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	d := webhook.New(webhook.Config{
		Enabled: true,
		URL:     srv.URL,
		Secret:  "s3cret",
		Timeout: "2s",
	}, "wireguardd", "v1.0.0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Emit(webhook.Event{Kind: "instance.up", Resource: "ovpn0", Message: "up"})
	require.Eventually(t, func() bool { return got.Load() == 1 }, 2*time.Second, 20*time.Millisecond)
	d.Close()

	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	require.Equal(t, want, sig)

	var e webhook.Event
	require.NoError(t, json.Unmarshal(body, &e))
	require.Equal(t, "wireguardd", e.Agent)
	require.Equal(t, "instance.up", e.Kind)
	require.Equal(t, "ovpn0", e.Resource)
}

func TestEventFilter(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	d := webhook.New(webhook.Config{
		Enabled: true,
		URL:     srv.URL,
		Events:  []string{"peer.*"},
		Timeout: "2s",
	}, "wireguardd", "t", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Emit(webhook.Event{Kind: "instance.up", Message: "x"})
	d.Emit(webhook.Event{Kind: "peer.connected", Message: "y"})
	require.Eventually(t, func() bool { return got.Load() >= 1 }, 2*time.Second, 20*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(1), got.Load())
	d.Close()
}
