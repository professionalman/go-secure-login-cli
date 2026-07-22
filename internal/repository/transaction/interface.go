package transaction

//go:generate go tool mockgen -source=interface.go -destination=mocks/mock_transaction.go -package=mocks

import (
	"context"

	sessionrepository "auth-cli/internal/repository/session"
	userrepository "auth-cli/internal/repository/user"
)

type IUnitOfWork interface {
	WithinTransaction(
		ctx context.Context,
		operation func(
			users userrepository.IUserRepository,
			sessions sessionrepository.ISessionRepository,
		) error,
	) error
}
