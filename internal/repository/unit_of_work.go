package repository

import "context"

type UnitOfWork interface {
	WithinTransaction(
		ctx context.Context,
		operation func(users UserRepository, sessions SessionRepository) error,
	) error
}
