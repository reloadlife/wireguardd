package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientAuthAndPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(VersionInfo{Version: "test"})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	c, err := NewClient(ts.URL, WithToken("secret"))
	require.NoError(t, err)
	require.NoError(t, c.Health(context.Background()))
	v, err := c.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, "test", v.Version)

	c2, err := NewClient(ts.URL, WithToken("wrong"))
	require.NoError(t, err)
	_, err = c2.Version(context.Background())
	require.Error(t, err)
}
