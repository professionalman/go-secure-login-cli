package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"auth-cli/migrations"
)

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`

type migration struct {
	version int
	name    string
}

// Migrate applies every pending embedded migration in version order.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("database is required")
	}
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}

	ordered, err := migrationFiles()
	if err != nil {
		return err
	}
	for _, item := range ordered {
		applied, err := migrationApplied(ctx, db, item.version)
		if err != nil {
			return fmt.Errorf("check migration %03d: %w", item.version, err)
		}
		if applied {
			continue
		}
		if err := applyMigration(ctx, db, item); err != nil {
			return err
		}
	}
	return nil
}

func migrationFiles() ([]migration, error) {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	seen := make(map[int]string)
	ordered := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("migration %q must start with a numeric version and underscore", entry.Name())
		}
		version, err := strconv.Atoi(parts[0])
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has an invalid version", entry.Name())
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("migrations %q and %q use duplicate version %d", previous, entry.Name(), version)
		}
		seen[version] = entry.Name()
		ordered = append(ordered, migration{version: version, name: entry.Name()})
	}
	if len(ordered) == 0 {
		return nil, fmt.Errorf("no embedded migrations found")
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].version < ordered[j].version
	})
	return ordered, nil
}

func migrationApplied(ctx context.Context, db *sql.DB, version int) (bool, error) {
	var exists int
	err := db.QueryRowContext(
		ctx,
		"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)",
		version,
	).Scan(&exists)
	return exists == 1, err
}

func applyMigration(ctx context.Context, db *sql.DB, item migration) error {
	contents, err := fs.ReadFile(migrations.Files, item.name)
	if err != nil {
		return fmt.Errorf("read migration %03d: %w", item.version, err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %03d: %w", item.version, err)
	}
	if _, err := tx.ExecContext(ctx, string(contents)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("apply migration %03d: %w", item.version, err)
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
		item.version,
		item.name,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("record migration %03d: %w", item.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %03d: %w", item.version, err)
	}
	return nil
}
