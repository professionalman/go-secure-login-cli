package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func Open(ctx context.Context, databaseURL string) (*sql.DB, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL database: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to PostgreSQL database: %w", err)
	}
	return db, nil
}
