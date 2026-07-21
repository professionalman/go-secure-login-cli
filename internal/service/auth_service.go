package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
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
	CompleteTOTPLogin(ctx context.Context, challengeID, code string) (*dto.LoginResult, error)
	CancelTOTPLogin(challengeID string)
	ClearTOTPLoginChallenges()
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

type LoginSecurityPolicy struct {
	MaximumAttempts int
	LockoutDuration time.Duration
}

type AuthOption func(*DefaultAuthService)

func WithSessionService(sessions SessionService) AuthOption {
	return func(service *DefaultAuthService) {
		service.sessions = sessions
	}
}

func WithLoginSecurityPolicy(policy LoginSecurityPolicy) AuthOption {
	return func(service *DefaultAuthService) {
		service.loginSecurity = &policy
	}
}

type DefaultAuthService struct {
	users          repository.UserRepository
	passwords      PasswordHasher
	verifier       PasswordVerifier
	sessions       SessionService
	clock          clock.Clock
	newID          func() string
	policy         RegistrationPolicy
	loginSecurity  *LoginSecurityPolicy
	totpEnrollment *totpEnrollmentDependencies
	totpLogin      *totpLoginDependencies
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

	now := s.clock.Now().UTC()
	if isLoginLocked(user, now) {
		return nil, domain.ErrAccountLocked
	}
	if err := s.verifier.Verify(user.PasswordHash, input.Password); err != nil {
		if err := s.recordFailedLogin(ctx, user, now); err != nil {
			if errors.Is(err, domain.ErrAccountLocked) {
				return nil, domain.ErrAccountLocked
			}
			return nil, fmt.Errorf("record failed login: %w", err)
		}
		return nil, domain.ErrInvalidCredentials
	}
	if user.TOTPEnabled {
		return s.beginTOTPLogin(user.ID, now)
	}
	if s.sessions == nil {
		return nil, fmt.Errorf("session service is not configured")
	}
	session, err := s.sessions.FinalizeLogin(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("finalize password login: %w", err)
	}
	return authenticatedLoginResult(session), nil
}

func authenticatedLoginResult(session *dto.SessionResult) *dto.LoginResult {
	return &dto.LoginResult{
		Status:            dto.LoginStatusAuthenticated,
		User:              session.User,
		RawSessionToken:   session.RawToken,
		SessionExpiresAt:  session.ExpiresAt,
		PreviousLastLogin: session.PreviousLastLogin,
	}
}

func (s *DefaultAuthService) recordFailedLogin(ctx context.Context, user *domain.User, now time.Time) error {
	if s.loginSecurity == nil {
		return nil
	}

	failedAttempts := user.FailedLoginAttempts
	if user.LockedUntil != nil && !user.LockedUntil.After(now) {
		failedAttempts = 0
	}
	failedAttempts++

	var lockedUntil *time.Time
	if failedAttempts >= s.loginSecurity.MaximumAttempts {
		deadline := now.Add(s.loginSecurity.LockoutDuration)
		lockedUntil = &deadline
	}
	if err := s.users.UpdateLoginFailureState(ctx, user.ID, failedAttempts, lockedUntil, now); err != nil {
		return err
	}
	if lockedUntil != nil {
		return domain.ErrAccountLocked
	}
	return nil
}

func isLoginLocked(user *domain.User, now time.Time) bool {
	return user.LockedUntil != nil && user.LockedUntil.After(now)
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
