package transaction_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sessionrepository "auth-cli/internal/repository/session"
	"auth-cli/internal/repository/transaction"
	userrepository "auth-cli/internal/repository/user"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresUnitOfWorkCommits(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	unitOfWork := transaction.NewPostgresUnitOfWork(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE users SET last_login_at = \\$1, updated_at = \\$1 WHERE id = \\$2").
		WithArgs(now, "user-id").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = unitOfWork.WithinTransaction(
		context.Background(),
		func(
			users userrepository.IUserRepository,
			_ sessionrepository.ISessionRepository,
		) error {
			return users.UpdateLastLogin(context.Background(), "user-id", now)
		},
	)
	if err != nil {
		t.Fatalf("WithinTransaction() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestPostgresUnitOfWorkRollsBackOperationError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	unitOfWork := transaction.NewPostgresUnitOfWork(db)
	operationError := errors.New("operation failed")

	mock.ExpectBegin()
	mock.ExpectRollback()

	err = unitOfWork.WithinTransaction(
		context.Background(),
		func(
			_ userrepository.IUserRepository,
			_ sessionrepository.ISessionRepository,
		) error {
			return operationError
		},
	)
	if !errors.Is(err, operationError) {
		t.Fatalf("WithinTransaction() error = %v, want operation error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestPostgresUnitOfWorkReturnsBeginError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	unitOfWork := transaction.NewPostgresUnitOfWork(db)
	beginError := errors.New("begin failed")

	mock.ExpectBegin().WillReturnError(beginError)

	err = unitOfWork.WithinTransaction(
		context.Background(),
		func(
			_ userrepository.IUserRepository,
			_ sessionrepository.ISessionRepository,
		) error {
			return nil
		},
	)
	if !errors.Is(err, beginError) {
		t.Fatalf("WithinTransaction() error = %v, want begin error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
