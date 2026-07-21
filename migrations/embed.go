package migrations

import "embed"

// Files contains the ordered SQL migrations compiled into the application.
//
//go:embed *.sql
var Files embed.FS
