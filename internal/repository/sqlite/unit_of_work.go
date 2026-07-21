package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"auth-cli/internal/repository"
)

type SQLiteUnitOfWork struct {
	db *sql.DB
}

func NewUnitOfWork(db *sql.DB) *SQLiteUnitOfWork {
	return &SQLiteUnitOfWork{db: db}
}

func (u *SQLiteUnitOfWork) WithinTransaction(
	ctx context.Context,
	operation func(users repository.UserRepository, sessions repository.SessionRepository) error,
) error {
	tx, err := u.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := operation(newUserRepository(tx), newSessionRepository(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
