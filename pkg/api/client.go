package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/reloadlife/wireguardd/pkg/wgutil"
)

// Client talks to wireguardd over HTTP or a Unix socket.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithToken sets the bearer token.
func WithToken(token string) ClientOption {
	return func(c *Client) { c.token = token }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithUnixSocket dials a Unix domain socket. baseURL should be like "http://localhost".
func WithUnixSocket(socketPath string) ClientOption {
	return func(c *Client) {
		c.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		}
		if c.baseURL == "" {
			c.baseURL = "http://localhost"
		}
	}
}

// NewClient creates an API client.
// urlOrUnix may be "http://host:port", "https://...", or "unix:///path/to.sock".
func NewClient(urlOrUnix string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	if strings.HasPrefix(urlOrUnix, "unix://") {
		path := strings.TrimPrefix(urlOrUnix, "unix://")
		c.baseURL = "http://localhost"
		WithUnixSocket(path)(c)
	} else {
		c.baseURL = strings.TrimRight(urlOrUnix, "/")
	}
	for _, o := range opts {
		o(c)
	}
	if c.baseURL == "" {
		return nil, fmt.Errorf("empty base URL")
	}
	return c, nil
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var eb ErrorBody
		if json.Unmarshal(data, &eb) == nil && eb.Error.Message != "" {
			return &APIError{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
		}
		return &APIError{Status: resp.StatusCode, Message: string(data)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Health checks /healthz.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil, nil)
}

// Version returns version info.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var v VersionInfo
	if err := c.do(ctx, http.MethodGet, "/v1/version", nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// BackendCapabilities returns host backend availability.
func (c *Client) BackendCapabilities(ctx context.Context) (*BackendCapabilities, error) {
	var out BackendCapabilities
	if err := c.do(ctx, "GET", "/v1/backends", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListInterfaces lists interfaces.
func (c *Client) ListInterfaces(ctx context.Context) ([]Interface, error) {
	var out []Interface
	if err := c.do(ctx, http.MethodGet, "/v1/interfaces", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetInterface returns one interface.
func (c *Client) GetInterface(ctx context.Context, name string) (*Interface, error) {
	var out Interface
	if err := c.do(ctx, http.MethodGet, "/v1/interfaces/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateInterface creates an interface.
// When req.CreateAWGPair is true, use CreateInterfacePair instead.
func (c *Client) CreateInterface(ctx context.Context, req InterfaceCreateRequest) (*Interface, error) {
	var out Interface
	if err := c.do(ctx, http.MethodPost, "/v1/interfaces", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateInterfacePair creates WG + AWG twin (listen_port and listen_port+10).
func (c *Client) CreateInterfacePair(ctx context.Context, req InterfaceCreateRequest) (*InterfacePairResponse, error) {
	req.CreateAWGPair = true
	var out InterfacePairResponse
	if err := c.do(ctx, http.MethodPost, "/v1/interfaces", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateInterface patches an interface.
func (c *Client) UpdateInterface(ctx context.Context, name string, req InterfaceUpdateRequest) (*Interface, error) {
	var out Interface
	if err := c.do(ctx, http.MethodPatch, "/v1/interfaces/"+url.PathEscape(name), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteInterface deletes an interface.
func (c *Client) DeleteInterface(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/interfaces/"+url.PathEscape(name), nil, nil)
}

// InterfaceUp brings an interface up.
func (c *Client) InterfaceUp(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/interfaces/"+url.PathEscape(name)+"/up", nil, nil)
}

// InterfaceDown brings an interface down.
func (c *Client) InterfaceDown(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/interfaces/"+url.PathEscape(name)+"/down", nil, nil)
}

// ExportInterface writes conf to disk on the daemon host.
func (c *Client) ExportInterface(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/interfaces/"+url.PathEscape(name)+"/export", nil, nil)
}

// ImportInterface imports a conf body.
func (c *Client) ImportInterface(ctx context.Context, name string, content string) (*Interface, error) {
	var out Interface
	req := ImportConfRequest{Content: content, Name: name}
	if err := c.do(ctx, http.MethodPost, "/v1/interfaces/"+url.PathEscape(name)+"/import", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPeers lists peers for an interface.
func (c *Client) ListPeers(ctx context.Context, iface string) ([]Peer, error) {
	var out []Peer
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers"
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListAllPeers lists all peers.
func (c *Client) ListAllPeers(ctx context.Context) ([]Peer, error) {
	var out []Peer
	if err := c.do(ctx, http.MethodGet, "/v1/stats/peers", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPeer gets a peer.
func (c *Client) GetPeer(ctx context.Context, iface, pubkey string) (*Peer, error) {
	var out Peer
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreatePeer creates a peer.
func (c *Client) CreatePeer(ctx context.Context, iface string, req PeerCreateRequest) (*Peer, error) {
	var out Peer
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers"
	if err := c.do(ctx, http.MethodPost, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePeer patches a peer.
func (c *Client) UpdatePeer(ctx context.Context, iface, pubkey string, req PeerUpdateRequest) (*Peer, error) {
	var out Peer
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey)
	if err := c.do(ctx, http.MethodPatch, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeletePeer deletes a peer.
func (c *Client) DeletePeer(ctx context.Context, iface, pubkey string) error {
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// SuspendPeer suspends a peer.
func (c *Client) SuspendPeer(ctx context.Context, iface, pubkey string) error {
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/suspend"
	return c.do(ctx, http.MethodPost, path, nil, nil)
}

// ResumePeer resumes a peer.
func (c *Client) ResumePeer(ctx context.Context, iface, pubkey string) error {
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/resume"
	return c.do(ctx, http.MethodPost, path, nil, nil)
}

// ResetPeerTraffic soft-resets counters.
func (c *Client) ResetPeerTraffic(ctx context.Context, iface, pubkey string) error {
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/reset-traffic"
	return c.do(ctx, http.MethodPost, path, nil, nil)
}

// PeerTraffic returns dual counters (accumulative + rates + windows) and optional history.
// from/to may be zero to use server defaults (last 1h).
func (c *Client) PeerTraffic(ctx context.Context, iface, pubkey string, from, to time.Time, limit int) (*PeerTrafficHistory, error) {
	var out PeerTrafficHistory
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/traffic"
	q := url.Values{}
	if !from.IsZero() {
		q.Set("from", from.UTC().Format(time.RFC3339Nano))
	}
	if !to.IsZero() {
		q.Set("to", to.UTC().Format(time.RFC3339Nano))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PeerClientConfig fetches client conf text.
func (c *Client) PeerClientConfig(ctx context.Context, iface, pubkey string) (string, error) {
	var out ClientConfigResponse
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/client-config"
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	return out.Config, nil
}

// PeerQR fetches the client config as a PNG QR code.
func (c *Client) PeerQR(ctx context.Context, iface, pubkey string) ([]byte, error) {
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/qr"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "image/png")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var eb ErrorBody
		if json.Unmarshal(data, &eb) == nil && eb.Error.Message != "" {
			return nil, &APIError{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
		}
		return nil, &APIError{Status: resp.StatusCode, Message: string(data)}
	}
	return data, nil
}

// IssueClientKey generates or returns a client private key + conf for a peer.
// Pass rotate=true for adopted peers (replaces peer public key).
func (c *Client) IssueClientKey(ctx context.Context, iface, pubkey string, rotate bool) (*IssueClientKeyResponse, error) {
	var out IssueClientKeyResponse
	path := "/v1/interfaces/" + url.PathEscape(iface) + "/peers/" + wgutil.PathEscapeKey(pubkey) + "/issue-client-key"
	if err := c.do(ctx, http.MethodPost, path, IssueClientKeyRequest{Rotate: rotate}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Discover previews live host WireGuard interfaces for adoption.
func (c *Client) Discover(ctx context.Context, names ...string) (*AdoptReport, error) {
	var out AdoptReport
	path := "/v1/discover"
	if len(names) > 0 {
		q := url.Values{}
		for _, n := range names {
			q.Add("name", n)
		}
		path += "?" + q.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Adopt imports live host WireGuard into the daemon DB without breaking host state.
func (c *Client) Adopt(ctx context.Context, req AdoptRequest) (*AdoptReport, error) {
	var out AdoptReport
	if err := c.do(ctx, http.MethodPost, "/v1/adopt", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GenerateKeys generates keys.
func (c *Client) GenerateKeys(ctx context.Context, typ string) (*KeyGenerateResponse, error) {
	var out KeyGenerateResponse
	if err := c.do(ctx, http.MethodPost, "/v1/keys/generate", KeyGenerateRequest{Type: typ}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListEvents lists events.
func (c *Client) ListEvents(ctx context.Context) ([]Event, error) {
	var out []Event
	if err := c.do(ctx, http.MethodGet, "/v1/events", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Stats returns global stats.
func (c *Client) Stats(ctx context.Context) (*StatsSummary, error) {
	var out StatsSummary
	if err := c.do(ctx, http.MethodGet, "/v1/stats", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Config returns non-secret daemon config.
func (c *Client) Config(ctx context.Context) (*DaemonConfig, error) {
	var out DaemonConfig
	if err := c.do(ctx, http.MethodGet, "/v1/config", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Reconcile forces a reconcile cycle.
func (c *Client) Reconcile(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/reconcile", nil, nil)
}
