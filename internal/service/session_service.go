package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth-cli/internal/clock"
	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
	"auth-cli/internal/security"
)

type SessionService interface {
	FinalizeLogin(ctx context.Context, userID string) (*dto.SessionResult, error)
	ValidateSession(ctx context.Context, rawToken string) (*dto.AuthenticatedUser, error)
	Logout(ctx context.Context, rawToken string) error
}

type SessionTokenGenerator func() (rawToken string, tokenHash string, err error)

type DefaultSessionService struct {
	users         repository.UserRepository
	sessions      repository.SessionRepository
	unitOfWork    repository.UnitOfWork
	clock         clock.Clock
	newID         func() string
	generateToken SessionTokenGenerator
	timeout       time.Duration
}

func NewSessionService(
	users repository.UserRepository,
	sessions repository.SessionRepository,
	unitOfWork repository.UnitOfWork,
	serviceClock clock.Clock,
	newID func() string,
	generateToken SessionTokenGenerator,
	timeout time.Duration,
) *DefaultSessionService {
	return &DefaultSessionService{
		users: users, sessions: sessions, unitOfWork: unitOfWork,
		clock: serviceClock, newID: newID, generateToken: generateToken, timeout: timeout,
	}
}

func (s *DefaultSessionService) FinalizeLogin(ctx context.Context, userID string) (*dto.SessionResult, error) {
	rawToken, tokenHash, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate session credentials: %w", err)
	}
	now := s.clock.Now().UTC()
	expiresAt := now.Add(s.timeout)
	session := &domain.Session{
		ID: s.newID(), UserID: userID, TokenHash: tokenHash,
		CreatedAt: now, ExpiresAt: expiresAt,
	}

	var user *domain.User
	err = s.unitOfWork.WithinTransaction(ctx, func(users repository.UserRepository, sessions repository.SessionRepository) error {
		found, err := users.FindByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("find login user: %w", err)
		}
		user = found
		if err := users.ResetLoginSecurity(ctx, userID, now); err != nil {
			return fmt.Errorf("reset login security: %w", err)
		}
		if err := sessions.Create(ctx, session); err != nil {
			return fmt.Errorf("create login session: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("finalize login: %w", err)
	}

	return &dto.SessionResult{
		RawToken:          rawToken,
		ExpiresAt:         expiresAt,
		User:              userDTO(user),
		PreviousLastLogin: copyTime(user.LastLoginAt),
	}, nil
}

func (s *DefaultSessionService) ValidateSession(ctx context.Context, rawToken string) (*dto.AuthenticatedUser, error) {
	if rawToken == "" {
		return nil, domain.ErrUnauthorized
	}
	session, err := s.sessions.FindByTokenHash(ctx, security.HashSessionToken(rawToken))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}
	if session.RevokedAt != nil {
		return nil, domain.ErrSessionRevoked
	}
	if !s.clock.Now().UTC().Before(session.ExpiresAt) {
		return nil, domain.ErrSessionExpired
	}
	user, err := s.users.FindByID(ctx, session.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("find session user: %w", err)
	}
	return &dto.AuthenticatedUser{User: userDTO(user), ExpiresAt: session.ExpiresAt}, nil
}

func (s *DefaultSessionService) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return domain.ErrUnauthorized
	}
	session, err := s.sessions.FindByTokenHash(ctx, security.HashSessionToken(rawToken))
	if errors.Is(err, repository.ErrNotFound) {
		return domain.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("find logout session: %w", err)
	}
	if session.RevokedAt != nil {
		return domain.ErrSessionRevoked
	}
	if !s.clock.Now().UTC().Before(session.ExpiresAt) {
		return domain.ErrSessionExpired
	}
	if err := s.sessions.Revoke(ctx, session.ID, s.clock.Now().UTC()); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return domain.ErrSessionRevoked
		}
		return fmt.Errorf("revoke logout session: %w", err)
	}
	return nil
}

func userDTO(user *domain.User) dto.User {
	return dto.User{
		ID: user.ID, Username: user.Username,
		TOTPEnabled: user.TOTPEnabled, RegisteredAt: user.RegisteredAt,
	}
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
