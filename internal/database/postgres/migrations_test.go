package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMigrateAppliesPendingMigrationsTransactionally(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectExec(`SELECT pg_advisory_lock\(\$1\)`).
		WithArgs(migrationLockID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))

	expectPendingMigration(mock, 1, "001_create_users.sql", "CREATE TABLE users")
	expectPendingMigration(mock, 2, "002_create_sessions.sql", "CREATE TABLE sessions")

	mock.ExpectExec(`SELECT pg_advisory_unlock\(\$1\)`).
		WithArgs(migrationLockID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	assertMigrationExpectations(t, mock)
}

func TestMigrateSkipsAlreadyAppliedMigrations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectExec(`SELECT pg_advisory_lock\(\$1\)`).
		WithArgs(migrationLockID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))
	for _, version := range []int{1, 2} {
		mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM schema_migrations WHERE version = \$1\)`).
			WithArgs(version).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	}
	mock.ExpectExec(`SELECT pg_advisory_unlock\(\$1\)`).
		WithArgs(migrationLockID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	assertMigrationExpectations(t, mock)
}

func TestMigrateRollsBackFailedMigration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	applyError := errors.New("invalid migration")

	mock.ExpectExec(`SELECT pg_advisory_lock\(\$1\)`).
		WithArgs(migrationLockID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM schema_migrations WHERE version = \$1\)`).
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectBegin()
	mock.ExpectExec("CREATE TABLE users").WillReturnError(applyError)
	mock.ExpectRollback()
	mock.ExpectExec(`SELECT pg_advisory_unlock\(\$1\)`).
		WithArgs(migrationLockID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = Migrate(context.Background(), db)
	if !errors.Is(err, applyError) {
		t.Fatalf("Migrate() error = %v, want wrapped migration error", err)
	}
	assertMigrationExpectations(t, mock)
}

func expectPendingMigration(
	mock sqlmock.Sqlmock,
	version int,
	name string,
	schemaPattern string,
) {
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM schema_migrations WHERE version = \$1\)`).
		WithArgs(version).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectBegin()
	mock.ExpectExec(schemaPattern).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO schema_migrations").
		WithArgs(version, name, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func assertMigrationExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
