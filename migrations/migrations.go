// Package migrations embeds the SQL migration files so the server binary is
// self-contained.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
