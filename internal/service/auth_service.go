package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"auth-cli/internal/clock"
	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
)

var safeUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type AuthService interface {
	Register(ctx context.Context, input dto.RegisterInput) (*dto.User, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type RegistrationPolicy struct {
	MinimumUsernameLength int
	MaximumUsernameLength int
	MinimumPasswordLength int
	MaximumPasswordLength int
}

type DefaultAuthService struct {
	users     repository.UserRepository
	passwords PasswordHasher
	clock     clock.Clock
	newID     func() string
	policy    RegistrationPolicy
}

func NewAuthService(
	users repository.UserRepository,
	passwords PasswordHasher,
	serviceClock clock.Clock,
	newID func() string,
	policy RegistrationPolicy,
) *DefaultAuthService {
	return &DefaultAuthService{
		users:     users,
		passwords: passwords,
		clock:     serviceClock,
		newID:     newID,
		policy:    policy,
	}
}

func (s *DefaultAuthService) Register(ctx context.Context, input dto.RegisterInput) (*dto.User, error) {
	username := strings.ToLower(strings.TrimSpace(input.Username))
	if !s.validUsername(username) {
		return nil, domain.ErrInvalidUsername
	}
	passwordLength := len([]byte(input.Password))
	if passwordLength < s.policy.MinimumPasswordLength || passwordLength > s.policy.MaximumPasswordLength {
		return nil, domain.ErrInvalidPassword
	}
	if input.Password != input.PasswordConfirmation {
		return nil, domain.ErrPasswordMismatch
	}

	_, err := s.users.FindByUsername(ctx, username)
	switch {
	case err == nil:
		return nil, domain.ErrUserAlreadyExists
	case !errors.Is(err, repository.ErrNotFound):
		return nil, fmt.Errorf("check username availability: %w", err)
	}

	passwordHash, err := s.passwords.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("secure password: %w", err)
	}
	now := s.clock.Now().UTC()
	user := &domain.User{
		ID:           s.newID(),
		Username:     username,
		PasswordHash: passwordHash,
		RegisteredAt: now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, domain.ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return &dto.User{
		ID:           user.ID,
		Username:     user.Username,
		TOTPEnabled:  user.TOTPEnabled,
		RegisteredAt: user.RegisteredAt,
	}, nil
}

func (s *DefaultAuthService) validUsername(username string) bool {
	length := len(username)
	return length >= s.policy.MinimumUsernameLength &&
		length <= s.policy.MaximumUsernameLength &&
		safeUsername.MatchString(username)
}
