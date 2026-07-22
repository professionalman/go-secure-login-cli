package transaction

import (
	"context"
	"database/sql"
	"fmt"

	sessionrepository "auth-cli/internal/repository/session"
	userrepository "auth-cli/internal/repository/user"
)

type PostgresUnitOfWork struct {
	db *sql.DB
}

func NewPostgresUnitOfWork(db *sql.DB) *PostgresUnitOfWork {
	return &PostgresUnitOfWork{db: db}
}

func (u *PostgresUnitOfWork) WithinTransaction(
	ctx context.Context,
	operation func(
		users userrepository.IUserRepository,
		sessions sessionrepository.ISessionRepository,
	) error,
) error {
	tx, err := u.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := operation(
		userrepository.NewPostgresRepositoryWithExecutor(tx),
		sessionrepository.NewPostgresRepositoryWithExecutor(tx),
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
