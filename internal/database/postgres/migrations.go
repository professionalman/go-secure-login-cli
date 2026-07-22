package postgres

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

const migrationLockID int64 = 71926021

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL
)`

type migration struct {
	version int
	name    string
}

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("database is required")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	if _, err := conn.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}
	ordered, err := migrationFiles()
	if err != nil {
		return err
	}
	for _, item := range ordered {
		var applied bool
		if err := conn.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", item.version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %03d: %w", item.version, err)
		}
		if applied {
			continue
		}
		if err := applyMigration(ctx, conn, item); err != nil {
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
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].version < ordered[j].version })
	return ordered, nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, item migration) error {
	contents, err := fs.ReadFile(migrations.Files, item.name)
	if err != nil {
		return fmt.Errorf("read migration %03d: %w", item.version, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %03d: %w", item.version, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, string(contents)); err != nil {
		return fmt.Errorf("apply migration %03d: %w", item.version, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations(version, name, applied_at) VALUES ($1, $2, $3)",
		item.version, item.name, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("record migration %03d: %w", item.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %03d: %w", item.version, err)
	}
	return nil
}
