// Package update implements self-update from GitHub Releases.
package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultRepo is the public GitHub repository for releases.
const DefaultRepo = "reloadlife/wireguardd"

// Component is which binary to update.
type Component string

const (
	ComponentDaemon Component = "wireguardd"
	ComponentCtl    Component = "wireguardctl"
)

// Info is a available release asset.
type Info struct {
	Tag         string
	Name        string // asset filename
	DownloadURL string // browser_download_url (public)
	APIURL      string // api asset url (needs Accept for private)
	Size        int64
}

// Options configures an update.
type Options struct {
	Repo      string // owner/name, default DefaultRepo
	Component Component
	// Current version string (from ldflags), e.g. "v0.7.1" or "dev".
	Current string
	// Target path to replace; empty = os.Executable().
	Target string
	// CheckOnly reports without downloading.
	CheckOnly bool
	// Force reinstalls even if versions match.
	Force bool
	// Token optional GitHub token for private/rate-limited API.
	Token string
	// HTTP client; nil uses a short-timeout default.
	HTTP *http.Client
}

// Result is the outcome of Check or Apply.
type Result struct {
	Current   string
	Latest    string
	UpToDate  bool
	Asset     string
	Installed string // path written (Apply only)
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
		URL                string `json:"url"`
	} `json:"assets"`
}

func (o *Options) normalize() error {
	if o.Repo == "" {
		o.Repo = DefaultRepo
	}
	if o.Component == "" {
		return fmt.Errorf("component required (wireguardd or wireguardctl)")
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 120 * time.Second}
	}
	if o.Token == "" {
		o.Token = firstEnv("GITHUB_TOKEN", "GH_TOKEN", "WIREGUARDD_GITHUB_TOKEN")
	}
	return nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// Check returns whether a newer release exists.
func Check(ctx context.Context, opts Options) (*Result, error) {
	if err := opts.normalize(); err != nil {
		return nil, err
	}
	info, err := latestAsset(ctx, opts)
	if err != nil {
		return nil, err
	}
	cur := normalizeVersion(opts.Current)
	lat := normalizeVersion(info.Tag)
	up := versionsEqual(cur, lat) && !opts.Force
	return &Result{
		Current:  displayVersion(opts.Current),
		Latest:   info.Tag,
		UpToDate: up,
		Asset:    info.Name,
	}, nil
}

// Apply downloads and replaces the running binary with the latest release.
func Apply(ctx context.Context, opts Options) (*Result, error) {
	if err := opts.normalize(); err != nil {
		return nil, err
	}
	res, err := Check(ctx, opts)
	if err != nil {
		return nil, err
	}
	if res.UpToDate {
		return res, nil
	}
	info, err := latestAsset(ctx, opts)
	if err != nil {
		return nil, err
	}

	target := opts.Target
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve executable: %w", err)
		}
		target, err = filepath.EvalSymlinks(exe)
		if err != nil {
			target = exe
		}
	}

	tmpDir, err := os.MkdirTemp("", "wireguardd-update-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	archivePath := filepath.Join(tmpDir, info.Name)
	if err := download(ctx, opts, info, archivePath); err != nil {
		return nil, err
	}

	binPath, err := extractBinary(archivePath, string(opts.Component), tmpDir)
	if err != nil {
		return nil, err
	}

	if err := replaceBinary(binPath, target); err != nil {
		return nil, err
	}
	res.Installed = target
	res.UpToDate = true
	res.Current = info.Tag
	return res, nil
}

func latestAsset(ctx context.Context, opts Options) (*Info, error) {
	api := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", opts.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wireguardd-updater")
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	}
	resp, err := opts.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github releases: HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, err
	}
	want := assetName(opts.Component, rel.TagName)
	for _, a := range rel.Assets {
		if a.Name == want {
			return &Info{
				Tag:         rel.TagName,
				Name:        a.Name,
				DownloadURL: a.BrowserDownloadURL,
				APIURL:      a.URL,
				Size:        a.Size,
			}, nil
		}
	}
	return nil, fmt.Errorf("no release asset %q for %s/%s (tag %s)", want, runtime.GOOS, runtime.GOARCH, rel.TagName)
}

func assetName(comp Component, tag string) string {
	ver := strings.TrimPrefix(tag, "v")
	switch comp {
	case ComponentDaemon:
		// wireguardd is Linux-only in releases
		return fmt.Sprintf("wireguardd_%s_linux_%s.tar.gz", ver, goarch())
	case ComponentCtl:
		return fmt.Sprintf("wireguardctl_%s_%s_%s.tar.gz", ver, runtime.GOOS, goarch())
	default:
		return ""
	}
}

func goarch() string {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH
	default:
		return runtime.GOARCH
	}
}

func download(ctx context.Context, opts Options, info *Info, dest string) error {
	// Prefer browser URL for public; use API URL with octet-stream when token set (private).
	u := info.DownloadURL
	accept := ""
	if opts.Token != "" && info.APIURL != "" {
		u = info.APIURL
		accept = "application/octet-stream"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wireguardd-updater")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	}
	resp, err := opts.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("download: HTTP %d: %s", resp.StatusCode, string(b))
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

func extractBinary(archivePath, binaryName, destDir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		base := filepath.Base(hdr.Name)
		if base != binaryName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		out := filepath.Join(destDir, binaryName)
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(w, tr); err != nil {
			_ = w.Close()
			return "", err
		}
		if err := w.Close(); err != nil {
			return "", err
		}
		return out, nil
	}
	return "", fmt.Errorf("binary %q not found in archive", binaryName)
}

func replaceBinary(src, dest string) error {
	// Write next to dest then rename for atomic-ish replace on same filesystem.
	dir := filepath.Dir(dest)
	tmp := filepath.Join(dir, "."+filepath.Base(dest)+".new")
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		// fallback: try /tmp then copy
		tmp = filepath.Join(os.TempDir(), filepath.Base(dest)+".new")
		out, err = os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create temp binary (need write to %s?): %w", dir, err)
		}
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Backup old binary
	bak := dest + ".bak"
	_ = os.Remove(bak)
	if err := os.Rename(dest, bak); err != nil && !os.IsNotExist(err) {
		// may be busy; try direct overwrite via copy to dest
		if err2 := copyFile(tmp, dest); err2 != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replace binary: %w (also: %v)", err, err2)
		}
		_ = os.Remove(tmp)
		return nil
	}
	if err := os.Rename(tmp, dest); err != nil {
		// restore backup
		_ = os.Rename(bak, dest)
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(bak)
	return nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	// strip build metadata like "v0.7.1-dirty" or "v0.7.1-5-gdeadbeef"
	if i := strings.IndexAny(v, "-+"); i > 0 {
		// keep prerelease after first - if it's like v1.0.0-rc.1 — only strip if looks like git describe
		rest := v[i+1:]
		if strings.HasPrefix(rest, "g") || rest == "dirty" || strings.Contains(rest, "-g") || strings.HasSuffix(rest, "dirty") {
			v = v[:i]
		} else if _, err := fmt.Sscanf(rest, "%d-", new(int)); err == nil {
			// "5-gdead" from git describe
			v = v[:i]
		}
	}
	return strings.TrimPrefix(v, "v")
}

func versionsEqual(a, b string) bool {
	return normalizeVersion(a) == normalizeVersion(b)
}

func displayVersion(v string) string {
	if v == "" || v == "dev" || v == "none" {
		return v
	}
	if !strings.HasPrefix(v, "v") && v != "dev" {
		return "v" + strings.TrimPrefix(normalizeVersion(v), "v")
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
