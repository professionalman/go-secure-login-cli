package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const busyTimeoutMilliseconds = 5000

// Open creates and validates a SQLite connection suitable for the single-user
// interactive application.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("database path is required")
	}

	if !isMemoryDatabase(path) && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	closeWithError := func(cause error) (*sql.DB, error) {
		_ = db.Close()
		return nil, cause
	}

	if err := db.PingContext(ctx); err != nil {
		return closeWithError(fmt.Errorf("connect to SQLite database: %w", err))
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return closeWithError(fmt.Errorf("enable SQLite foreign keys: %w", err))
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeoutMilliseconds)); err != nil {
		return closeWithError(fmt.Errorf("set SQLite busy timeout: %w", err))
	}
	if !isMemoryDatabase(path) {
		var mode string
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode); err != nil {
			return closeWithError(fmt.Errorf("enable SQLite WAL mode: %w", err))
		}
		if !strings.EqualFold(mode, "wal") {
			return closeWithError(fmt.Errorf("SQLite refused WAL mode"))
		}
	}

	var foreignKeys int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return closeWithError(fmt.Errorf("verify SQLite foreign keys: %w", err))
	}
	if foreignKeys != 1 {
		return closeWithError(fmt.Errorf("SQLite foreign-key enforcement is disabled"))
	}

	return db, nil
}

func isMemoryDatabase(path string) bool {
	lower := strings.ToLower(path)
	return path == ":memory:" || strings.Contains(lower, "mode=memory")
}
