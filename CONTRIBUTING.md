# Contributing

Thanks for contributing to wireguardd.

## Development

```bash
# Go 1.24+
make deps
make test
make lint   # requires golangci-lint
make build
```

- Format with `gofmt`
- Prefer small, focused PRs
- Add tests for bug fixes and new behavior when practical
- Do not commit secrets, private keys, or host-specific configs

## Project layout

| Path | Role |
|------|------|
| `cmd/wireguardd` | Daemon CLI |
| `cmd/wireguardctl` | Control panel CLI + TUI |
| `internal/` | Implementation (not a stable public API) |
| `pkg/api` | HTTP client + types (usable by integrations) |
| `migrations/` | SQLite schema (goose) |
| `configs/` | Example configs only |
| `scripts/install.sh` | Release installer |

## License

By contributing, you agree that your contributions are licensed under the
[AGPL-3.0](LICENSE) license of this project.
