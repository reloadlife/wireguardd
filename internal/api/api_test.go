package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/api"
	"github.com/reloadlife/wireguardd/internal/config"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/reconcile"
	"github.com/reloadlife/wireguardd/internal/stats"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func setupServer(t *testing.T) (*api.Server, *db.Store, *wgbackend.MockBackend) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	store, err := db.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	backend := wgbackend.NewMock()
	cache := stats.NewCache()
	cfg := &config.DaemonConfig{}
	cfg.Auth.Token = "test-token"
	cfg.WireGuard.ConfDir = t.TempDir()
	cfg.WireGuard.Persistence = "hybrid"
	cfg.WireGuard.HandshakeConnectedSec = 180
	cfg.WireGuard.AllowHooks = false
	cfg.Listen.HTTP = "127.0.0.1:0"
	rec := reconcile.New(store, backend, cache, reconcile.Config{
		Persistence: "hybrid",
		ConfDir:     cfg.WireGuard.ConfDir,
	}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	srv := api.NewServer(store, backend, cache, rec, cfg, nil)
	return srv, store, backend
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any, want int) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, want, rr.Code, rr.Body.String())
	return rr
}

func TestHealthAndAuth(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := srv.Router()
	doJSON(t, h, http.MethodGet, "/healthz", "", nil, http.StatusOK)
	doJSON(t, h, http.MethodGet, "/v1/version", "", nil, http.StatusUnauthorized)
	doJSON(t, h, http.MethodGet, "/v1/version", "test-token", nil, http.StatusOK)
}

func TestInterfacePeerLifecycle(t *testing.T) {
	srv, store, backend := setupServer(t)
	h := srv.Router()
	token := "test-token"

	// create iface
	rr := doJSON(t, h, http.MethodPost, "/v1/interfaces", token, pkgapi.InterfaceCreateRequest{
		Name:       "wg0",
		ListenPort: 51820,
		Addresses:  []string{"10.8.0.1/24"},
	}, http.StatusCreated)
	var iface pkgapi.Interface
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &iface))
	require.Equal(t, "wg0", iface.Name)
	require.NotEmpty(t, iface.PublicKey)

	// list
	rr = doJSON(t, h, http.MethodGet, "/v1/interfaces", token, nil, http.StatusOK)
	var list []pkgapi.Interface
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 1)

	// keys
	rr = doJSON(t, h, http.MethodPost, "/v1/keys/generate", token, pkgapi.KeyGenerateRequest{Type: "keypair"}, http.StatusOK)
	var keys pkgapi.KeyGenerateResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &keys))
	require.NotEmpty(t, keys.PublicKey)

	// peer
	rr = doJSON(t, h, http.MethodPost, "/v1/interfaces/wg0/peers", token, pkgapi.PeerCreateRequest{
		PublicKey:   keys.PublicKey,
		Name:        "alice",
		AllowedIPs:  []string{"10.8.0.2/32"},
		AssignedIPs: []string{"10.8.0.2"},
		GeneratePSK: true,
	}, http.StatusCreated)
	var peer pkgapi.Peer
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &peer))
	require.Equal(t, "alice", peer.Name)
	require.NotEmpty(t, peer.PresharedKey)

	// suspend
	doJSON(t, h, http.MethodPost, "/v1/interfaces/wg0/peers/"+keys.PublicKey+"/suspend", token, nil, http.StatusOK)
	p, err := store.GetPeer(context.Background(), "wg0", keys.PublicKey)
	require.NoError(t, err)
	require.True(t, p.Suspended)

	// resume
	doJSON(t, h, http.MethodPost, "/v1/interfaces/wg0/peers/"+keys.PublicKey+"/resume", token, nil, http.StatusOK)

	// stats
	doJSON(t, h, http.MethodGet, "/v1/stats", token, nil, http.StatusOK)
	doJSON(t, h, http.MethodGet, "/v1/events", token, nil, http.StatusOK)

	// export
	doJSON(t, h, http.MethodPost, "/v1/interfaces/wg0/export", token, nil, http.StatusOK)

	// down / up
	doJSON(t, h, http.MethodPost, "/v1/interfaces/wg0/down", token, nil, http.StatusOK)
	doJSON(t, h, http.MethodPost, "/v1/interfaces/wg0/up", token, nil, http.StatusOK)

	// client config
	doJSON(t, h, http.MethodGet, "/v1/interfaces/wg0/peers/"+keys.PublicKey+"/client-config", token, nil, http.StatusOK)

	// delete peer
	req := httptest.NewRequest(http.MethodDelete, "/v1/interfaces/wg0/peers/"+keys.PublicKey, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNoContent, rr.Code)

	// delete iface
	req = httptest.NewRequest(http.MethodDelete, "/v1/interfaces/wg0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNoContent, rr.Code)

	_, err = backend.Device(context.Background(), "wg0")
	require.Error(t, err)
}

func TestClientAgainstServer(t *testing.T) {
	srv, _, _ := setupServer(t)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	client, err := pkgapi.NewClient(ts.URL, pkgapi.WithToken("test-token"))
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, client.Health(ctx))
	v, err := client.Version(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, v.Version)

	iface, err := client.CreateInterface(ctx, pkgapi.InterfaceCreateRequest{
		Name: "wg1", ListenPort: 51821, Addresses: []string{"10.9.0.1/24"},
	})
	require.NoError(t, err)
	require.Equal(t, "wg1", iface.Name)

	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	peer, err := client.CreatePeer(ctx, "wg1", pkgapi.PeerCreateRequest{
		PublicKey: kp.PublicKey, Name: "bob", AllowedIPs: []string{"10.9.0.2/32"},
	})
	require.NoError(t, err)
	require.Equal(t, "bob", peer.Name)

	st, err := client.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, st.Interfaces)
	require.Equal(t, 1, st.Peers)
}
