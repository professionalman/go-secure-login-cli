package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateCreatesSchemaAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 2 {
		t.Errorf("applied migration count = %d, want 2", count)
	}

	for _, table := range []string{"users", "sessions"} {
		var exists int
		if err := db.QueryRowContext(
			ctx,
			"SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
			table,
		).Scan(&exists); err != nil {
			t.Fatalf("look up table %q: %v", table, err)
		}
		if exists != 1 {
			t.Errorf("table %q was not created", table)
		}
	}
}

func TestOpenEnablesForeignKeysAndWAL(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var foreignKeys int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestUsersTOTPConstraint(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (
			id, username, password_hash, totp_enabled, totp_secret_encrypted,
			registered_at, created_at, updated_at
		) VALUES (?, ?, ?, 0, ?, ?, ?, ?)`,
		"user-id", "alice", "hash", "secret", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
	)
	if err == nil {
		t.Fatal("inserting a disabled TOTP user with a secret succeeded, want constraint error")
	}
}
