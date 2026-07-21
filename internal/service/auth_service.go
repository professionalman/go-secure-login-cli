package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"auth-cli/internal/clock"
	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
)

const dummyPasswordHash = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"

var safeUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type AuthService interface {
	Register(ctx context.Context, input dto.RegisterInput) (*dto.User, error)
}

type LoginService interface {
	LoginWithPassword(ctx context.Context, input dto.LoginInput) (*dto.LoginResult, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type PasswordVerifier interface {
	Verify(passwordHash, password string) error
}

type RegistrationPolicy struct {
	MinimumUsernameLength int
	MaximumUsernameLength int
	MinimumPasswordLength int
	MaximumPasswordLength int
}

type AuthOption func(*DefaultAuthService)

func WithSessionService(sessions SessionService) AuthOption {
	return func(service *DefaultAuthService) {
		service.sessions = sessions
	}
}

type DefaultAuthService struct {
	users     repository.UserRepository
	passwords PasswordHasher
	verifier  PasswordVerifier
	sessions  SessionService
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
	options ...AuthOption,
) *DefaultAuthService {
	service := &DefaultAuthService{
		users:     users,
		passwords: passwords,
		clock:     serviceClock,
		newID:     newID,
		policy:    policy,
	}
	service.verifier, _ = passwords.(PasswordVerifier)
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *DefaultAuthService) Register(ctx context.Context, input dto.RegisterInput) (*dto.User, error) {
	username := normalizeUsername(input.Username)
	if !s.validUsername(username) {
		return nil, domain.ErrInvalidUsername
	}
	passwordLength := len([]byte(input.Password))
	if !utf8.ValidString(input.Password) ||
		passwordLength < s.policy.MinimumPasswordLength ||
		passwordLength > s.policy.MaximumPasswordLength {
		return nil, domain.ErrInvalidPassword
	}
	if input.Password != input.PasswordConfirmation {
		return nil, domain.ErrPasswordMismatch
	}

	if _, err := s.users.FindByUsername(ctx, username); err == nil {
		return nil, domain.ErrUserAlreadyExists
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("check username availability: %w", err)
	}

	passwordHash, err := s.passwords.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
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
	result := userDTO(user)
	return &result, nil
}

func (s *DefaultAuthService) LoginWithPassword(ctx context.Context, input dto.LoginInput) (*dto.LoginResult, error) {
	if s.verifier == nil {
		return nil, fmt.Errorf("password verifier is not configured")
	}
	username := normalizeUsername(input.Username)
	user, err := s.users.FindByUsername(ctx, username)
	if errors.Is(err, repository.ErrNotFound) {
		_ = s.verifier.Verify(dummyPasswordHash, input.Password)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("find login user: %w", err)
	}
	if err := s.verifier.Verify(user.PasswordHash, input.Password); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if user.TOTPEnabled {
		// Challenge creation and TOTP completion are implemented in Milestone 6.
		return &dto.LoginResult{Status: dto.LoginStatusTOTPRequired}, nil
	}
	if s.sessions == nil {
		return nil, fmt.Errorf("session service is not configured")
	}
	session, err := s.sessions.FinalizeLogin(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("finalize password login: %w", err)
	}
	return &dto.LoginResult{
		Status:            dto.LoginStatusAuthenticated,
		User:              session.User,
		RawSessionToken:   session.RawToken,
		SessionExpiresAt:  session.ExpiresAt,
		PreviousLastLogin: session.PreviousLastLogin,
	}, nil
}

func (s *DefaultAuthService) validUsername(username string) bool {
	length := len(username)
	return length >= s.policy.MinimumUsernameLength &&
		length <= s.policy.MaximumUsernameLength &&
		safeUsername.MatchString(username)
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}
