# Security Policy

## Supported versions

Security fixes are applied to the latest release on `main` and published as a new tagged release.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email the maintainer listed on the GitHub repository profile, or open a
**private** security advisory on GitHub (Security → Advisories → Report a vulnerability).

Include:

- Affected version / commit
- Reproduction steps
- Impact assessment (privilege, remote exploitability, data exposure)

You should receive an acknowledgement within a few days.

## Hardening checklist (operators)

- Change `auth.token` from the default **before** exposing the API
- Bind the API to `127.0.0.1` or a Unix socket; put TLS/auth in front if remote
- Keep `wireguard.allow_hooks: false` unless you trust every API client
- Restrict file permissions: config, SQLite DBs, and `/etc/wireguard/*.conf` should be `0600` root-only
- Do not commit real tokens, private keys, or production configs into git
