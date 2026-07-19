package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

// Creating an interface that already exists in the kernel must ADOPT its key,
// never mint a new one.
//
// A WireGuard interface's private key is its identity: every peer holds the
// matching public key. Rotating it does not fail loudly — the interface simply
// stops answering peers that no longer recognise it, with no log line on either
// side, which looks exactly like the link being down.
//
// That is how sky-ams-1 left the control-plane mesh for over three hours on
// 2026-07-19 while SSH and every daemon on it stayed healthy.
func TestCreateInterfaceAdoptsExistingKernelKey(t *testing.T) {
	srv, _, backend := setupServer(t)
	h := srv.Router()

	// An interface already live in the kernel, as mesh0 is.
	existing, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	backend.DevicesM["mesh0"] = &wgbackend.Device{
		Name:       "mesh0",
		PrivateKey: existing.PrivateKey,
		PublicKey:  existing.PublicKey,
	}

	rr := doJSON(t, h, http.MethodPost, "/v1/interfaces", "test-token",
		pkgapi.InterfaceCreateRequest{Name: "mesh0", Addresses: []string{"10.66.0.2/32"}},
		http.StatusCreated)

	var got pkgapi.Interface
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Equal(t, existing.PublicKey, got.PublicKey,
		"created interface must keep the key its peers already trust, not a fresh one")
}

// A genuinely new interface still gets a generated key — the guard must not
// block normal provisioning.
func TestCreateNewInterfaceStillGeneratesKey(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := srv.Router()

	rr := doJSON(t, h, http.MethodPost, "/v1/interfaces", "test-token",
		pkgapi.InterfaceCreateRequest{Name: "wg-brand-new", Addresses: []string{"10.9.0.1/24"}},
		http.StatusCreated)

	var got pkgapi.Interface
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.NotEmpty(t, got.PublicKey, "a new interface must still get a key")
}
