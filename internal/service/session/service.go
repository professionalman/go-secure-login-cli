package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
	sessionrepository "auth-cli/internal/repository/session"
	"auth-cli/internal/repository/transaction"
	userrepository "auth-cli/internal/repository/user"
	"auth-cli/internal/security"
)

type TokenGenerator func() (rawToken string, tokenHash string, err error)

type Service struct {
	users         userrepository.IUserRepository
	sessions      sessionrepository.ISessionRepository
	unitOfWork    transaction.IUnitOfWork
	newID         func() string
	generateToken TokenGenerator
	timeout       time.Duration
}

func NewService(
	users userrepository.IUserRepository,
	sessions sessionrepository.ISessionRepository,
	unitOfWork transaction.IUnitOfWork,
	newID func() string,
	generateToken TokenGenerator,
	timeout time.Duration,
) *Service {
	return &Service{
		users: users, sessions: sessions, unitOfWork: unitOfWork,
		newID: newID, generateToken: generateToken, timeout: timeout,
	}
}

func (s *Service) FinalizeLogin(ctx context.Context, userID string) (*dto.SessionResult, error) {
	rawToken, tokenHash, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate session credentials: %w", err)
	}
	now := time.Now().UTC()
	value := &domain.Session{
		ID: s.newID(), UserID: userID, TokenHash: tokenHash,
		CreatedAt: now, ExpiresAt: now.Add(s.timeout),
	}
	var found *domain.User
	err = s.unitOfWork.WithinTransaction(ctx, func(
		users userrepository.IUserRepository,
		sessions sessionrepository.ISessionRepository,
	) error {
		user, err := users.FindByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("find login user: %w", err)
		}
		found = user
		if err := users.UpdateLastLogin(ctx, userID, now); err != nil {
			return fmt.Errorf("update last login: %w", err)
		}
		if err := sessions.Create(ctx, value); err != nil {
			return fmt.Errorf("create login session: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("finalize login: %w", err)
	}
	return &dto.SessionResult{
		RawToken: rawToken, ExpiresAt: value.ExpiresAt,
		User: userDTO(found), PreviousLastLogin: copyTime(found.LastLoginAt),
	}, nil
}

func (s *Service) ValidateSession(ctx context.Context, rawToken string) (*dto.AuthenticatedUser, error) {
	if rawToken == "" {
		return nil, domain.ErrUnauthorized
	}
	value, err := s.sessions.FindByTokenHash(ctx, security.HashSessionToken(rawToken))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}
	if value.RevokedAt != nil {
		return nil, domain.ErrSessionRevoked
	}
	if !time.Now().UTC().Before(value.ExpiresAt) {
		return nil, domain.ErrSessionExpired
	}
	user, err := s.users.FindByID(ctx, value.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("find session user: %w", err)
	}
	return &dto.AuthenticatedUser{User: userDTO(user), ExpiresAt: value.ExpiresAt}, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return domain.ErrUnauthorized
	}
	value, err := s.sessions.FindByTokenHash(ctx, security.HashSessionToken(rawToken))
	if errors.Is(err, repository.ErrNotFound) {
		return domain.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("find logout session: %w", err)
	}
	if value.RevokedAt != nil {
		return domain.ErrSessionRevoked
	}
	if !time.Now().UTC().Before(value.ExpiresAt) {
		return domain.ErrSessionExpired
	}
	if err := s.sessions.Revoke(ctx, value.ID, time.Now().UTC()); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return domain.ErrSessionRevoked
		}
		return fmt.Errorf("revoke logout session: %w", err)
	}
	return nil
}

func userDTO(value *domain.User) dto.User {
	return dto.User{
		ID: value.ID, Username: value.Username,
		TOTPEnabled: value.TOTPEnabled, RegisteredAt: value.RegisteredAt,
	}
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
