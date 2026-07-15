// Package webhook delivers agent events to an external controller over HTTP.
//
// Delivery is best-effort, at-most-once from the agent’s perspective (bounded
// queue; drops when full). Controllers should still poll for eventual consistency.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config is loaded from daemon YAML (webhooks.*).
type Config struct {
	Enabled bool     `mapstructure:"enabled" yaml:"enabled"`
	URL     string   `mapstructure:"url" yaml:"url"`
	Secret  string   `mapstructure:"secret" yaml:"secret"` // optional HMAC-SHA256 key
	Events  []string `mapstructure:"events" yaml:"events"` // empty or ["*"] = all
	Timeout string   `mapstructure:"timeout" yaml:"timeout"` // e.g. 5s
	// QueueSize bounds in-flight events (default 256).
	QueueSize int `mapstructure:"queue_size" yaml:"queue_size"`
}

// Event is the JSON body POSTed to the controller.
type Event struct {
	Agent     string          `json:"agent"`
	Version   string          `json:"version,omitempty"`
	ID        int64           `json:"id,omitempty"`
	TS        time.Time       `json:"ts"`
	Level     string          `json:"level"`
	Kind      string          `json:"kind"`
	Resource  string          `json:"resource,omitempty"` // instance name (openvpnd)
	Subject   string          `json:"subject,omitempty"`  // client CN / peer key
	Message   string          `json:"message"`
	Meta      json.RawMessage `json:"meta,omitempty"`
}

// Dispatcher posts events asynchronously.
type Dispatcher struct {
	cfg     Config
	agent   string
	version string
	log     *slog.Logger
	client  *http.Client
	ch      chan Event
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
}

// New builds a dispatcher. Call Start to run the worker.
func New(cfg Config, agent, version string, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	timeout := 5 * time.Second
	if d, err := time.ParseDuration(strings.TrimSpace(cfg.Timeout)); err == nil && d > 0 {
		timeout = d
	}
	q := cfg.QueueSize
	if q <= 0 {
		q = 256
	}
	return &Dispatcher{
		cfg:     cfg,
		agent:   agent,
		version: version,
		log:     log,
		client:  &http.Client{Timeout: timeout},
		ch:      make(chan Event, q),
	}
}

// Enabled reports whether delivery is configured.
func (d *Dispatcher) Enabled() bool {
	if d == nil {
		return false
	}
	return d.cfg.Enabled && strings.TrimSpace(d.cfg.URL) != ""
}

// Start launches the background worker until ctx is cancelled or Close.
func (d *Dispatcher) Start(parent context.Context) {
	if d == nil || !d.Enabled() {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	d.cancel = cancel
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.loop(ctx)
	}()
	d.log.Info("webhooks enabled", "url", d.cfg.URL, "events", d.cfg.Events)
}

// Close stops the worker and drains the queue (best-effort).
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	d.mu.Unlock()
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

// Emit enqueues an event. No-op if disabled. Drops if queue is full.
func (d *Dispatcher) Emit(e Event) {
	if d == nil || !d.Enabled() {
		return
	}
	if !d.match(e.Kind) {
		return
	}
	if e.Agent == "" {
		e.Agent = d.agent
	}
	if e.Version == "" {
		e.Version = d.version
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if e.Level == "" {
		e.Level = "info"
	}
	if len(e.Meta) == 0 {
		e.Meta = json.RawMessage(`{}`)
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return
	}
	select {
	case d.ch <- e:
	default:
		d.log.Warn("webhook queue full; dropping event", "kind", e.Kind, "resource", e.Resource)
	}
}

// EmitFromStore is a convenience for db.AddEvent hooks.
func (d *Dispatcher) EmitFromStore(level, kind, resource, subject, message, meta string) {
	raw := json.RawMessage(`{}`)
	if strings.TrimSpace(meta) != "" && json.Valid([]byte(meta)) {
		raw = json.RawMessage(meta)
	}
	d.Emit(Event{
		Level:    level,
		Kind:     kind,
		Resource: resource,
		Subject:  subject,
		Message:  message,
		Meta:     raw,
	})
}

func (d *Dispatcher) match(kind string) bool {
	if len(d.cfg.Events) == 0 {
		return true
	}
	for _, e := range d.cfg.Events {
		e = strings.TrimSpace(e)
		if e == "" || e == "*" {
			return true
		}
		if strings.EqualFold(e, kind) {
			return true
		}
		// prefix match: "peer.*" or "instance."
		if strings.HasSuffix(e, ".*") {
			prefix := strings.TrimSuffix(e, ".*")
			if strings.HasPrefix(kind, prefix+".") || kind == prefix {
				return true
			}
		}
	}
	return false
}

func (d *Dispatcher) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// drain quickly without blocking shutdown long
			for {
				select {
				case e := <-d.ch:
					_ = d.post(context.Background(), e)
				default:
					return
				}
			}
		case e := <-d.ch:
			if err := d.post(ctx, e); err != nil {
				d.log.Warn("webhook delivery failed", "kind", e.Kind, "err", err)
			}
		}
	}
}

func (d *Dispatcher) post(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", d.agent+"-webhook/1.0")
	req.Header.Set("X-Agent", d.agent)
	req.Header.Set("X-Event-Kind", e.Kind)
	if sec := strings.TrimSpace(d.cfg.Secret); sec != "" {
		mac := hmac.New(sha256.New, []byte(sec))
		_, _ = mac.Write(body)
		req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
