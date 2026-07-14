package migrations

import "embed"

// FS holds SQL migration files.
//
//go:embed *.sql
var FS embed.FS
