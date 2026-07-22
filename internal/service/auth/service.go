package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
	"auth-cli/internal/repository/loginsecurity"
	userrepository "auth-cli/internal/repository/user"
	"auth-cli/internal/security"
	sessionservice "auth-cli/internal/service/session"
	totpservice "auth-cli/internal/service/totp"
)

const dummyPasswordHash = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"

var safeUsername = regexp.MustCompile("^[a-z0-9][a-z0-9._-]*$")

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

type TokenGenerator func() (rawToken string, tokenHash string, err error)

type pendingLogin struct {
	userID    string
	expiresAt time.Time
}

type Service struct {
	users            userrepository.IUserRepository
	passwords        security.IPasswordManager
	sessions         sessionservice.ISessionService
	totp             totpservice.ITOTPService
	loginSecurity    loginsecurity.ILoginSecurityRepository
	newID            func() string
	generateToken    TokenGenerator
	registration     RegistrationPolicy
	securityPolicy   LoginSecurityPolicy
	challengeTimeout time.Duration
	mu               sync.Mutex
	challenges       map[string]pendingLogin
}

func NewService(
	users userrepository.IUserRepository,
	passwords security.IPasswordManager,
	sessions sessionservice.ISessionService,
	totp totpservice.ITOTPService,
	loginSecurity loginsecurity.ILoginSecurityRepository,
	newID func() string,
	generateToken TokenGenerator,
	registration RegistrationPolicy,
	securityPolicy LoginSecurityPolicy,
	challengeTimeout time.Duration,
) *Service {
	return &Service{
		users: users, passwords: passwords, sessions: sessions, totp: totp,
		loginSecurity: loginSecurity, newID: newID, generateToken: generateToken,
		registration: registration, securityPolicy: securityPolicy,
		challengeTimeout: challengeTimeout, challenges: make(map[string]pendingLogin),
	}
}

func (s *Service) Register(ctx context.Context, input dto.RegisterInput) (*dto.User, error) {
	username := normalizeUsername(input.Username)
	if !s.validUsername(username) {
		return nil, domain.ErrInvalidUsername
	}
	length := len([]byte(input.Password))
	if !utf8.ValidString(input.Password) ||
		length < s.registration.MinimumPasswordLength ||
		length > s.registration.MaximumPasswordLength {
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
	hash, err := s.passwords.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	value := &domain.User{
		ID: s.newID(), Username: username, PasswordHash: hash,
		RegisteredAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.users.Create(ctx, value); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, domain.ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	result := userDTO(value)
	return &result, nil
}

func (s *Service) LoginWithPassword(ctx context.Context, input dto.LoginInput) (*dto.LoginResult, error) {
	username := normalizeUsername(input.Username)
	user, err := s.users.FindByUsername(ctx, username)
	if errors.Is(err, repository.ErrNotFound) {
		_ = s.passwords.Verify(dummyPasswordHash, input.Password)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("find login user: %w", err)
	}
	blocked, err := s.loginSecurity.IsBlocked(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("check account lockout: %w", err)
	}
	if blocked {
		return nil, domain.ErrAccountLocked
	}
	if err := s.passwords.Verify(user.PasswordHash, input.Password); err != nil {
		return nil, s.failedLogin(ctx, user.ID, domain.ErrInvalidCredentials)
	}
	if user.TOTPEnabled {
		return s.beginTOTPLogin(user.ID)
	}
	return s.finishLogin(ctx, user.ID)
}

func (s *Service) CompleteTOTPLogin(
	ctx context.Context,
	challengeID string,
	code string,
) (*dto.LoginResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, found := s.challenges[challengeID]
	if !found {
		return nil, domain.ErrTOTPChallengeNotFound
	}
	now := time.Now().UTC()
	if !now.Before(challenge.expiresAt) {
		delete(s.challenges, challengeID)
		return nil, domain.ErrTOTPChallengeExpired
	}
	user, err := s.users.FindByID(ctx, challenge.userID)
	if errors.Is(err, repository.ErrNotFound) {
		delete(s.challenges, challengeID)
		return nil, domain.ErrTOTPChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find TOTP login user: %w", err)
	}
	blocked, err := s.loginSecurity.IsBlocked(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("check account lockout: %w", err)
	}
	if blocked {
		delete(s.challenges, challengeID)
		return nil, domain.ErrAccountLocked
	}
	if !user.TOTPEnabled || user.TOTPSecretEncrypted == nil {
		delete(s.challenges, challengeID)
		return nil, domain.ErrTOTPNotEnabled
	}
	valid, err := s.totp.ValidateEncryptedCode(*user.TOTPSecretEncrypted, code)
	if err != nil {
		return nil, fmt.Errorf("validate TOTP login code: %w", err)
	}
	if !valid {
		err := s.failedLogin(ctx, user.ID, domain.ErrInvalidTOTP)
		if errors.Is(err, domain.ErrAccountLocked) {
			delete(s.challenges, challengeID)
		}
		return nil, err
	}
	result, err := s.finishLogin(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	delete(s.challenges, challengeID)
	return result, nil
}

func (s *Service) CancelTOTPLogin(challengeID string) {
	s.mu.Lock()
	delete(s.challenges, challengeID)
	s.mu.Unlock()
}

func (s *Service) ClearTOTPLoginChallenges() {
	s.mu.Lock()
	s.challenges = make(map[string]pendingLogin)
	s.mu.Unlock()
}

func (s *Service) beginTOTPLogin(userID string) (*dto.LoginResult, error) {
	challengeID, _, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate TOTP login challenge: %w", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(s.challengeTimeout)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, value := range s.challenges {
		if !now.Before(value.expiresAt) {
			delete(s.challenges, id)
		}
	}
	if _, exists := s.challenges[challengeID]; exists {
		return nil, fmt.Errorf("generated a duplicate TOTP login challenge")
	}
	s.challenges[challengeID] = pendingLogin{userID: userID, expiresAt: expiresAt}
	return &dto.LoginResult{
		Status:      dto.LoginStatusTOTPRequired,
		ChallengeID: challengeID, ChallengeExpiresAt: expiresAt,
	}, nil
}

func (s *Service) finishLogin(ctx context.Context, userID string) (*dto.LoginResult, error) {
	if err := s.loginSecurity.Reset(ctx, userID); err != nil {
		return nil, fmt.Errorf("reset login security: %w", err)
	}
	result, err := s.sessions.FinalizeLogin(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("finalize login: %w", err)
	}
	return &dto.LoginResult{
		Status: dto.LoginStatusAuthenticated, User: result.User,
		RawSessionToken: result.RawToken, SessionExpiresAt: result.ExpiresAt,
		PreviousLastLogin: result.PreviousLastLogin,
	}, nil
}

func (s *Service) failedLogin(ctx context.Context, userID string, failure error) error {
	blocked, err := s.loginSecurity.RecordFailure(
		ctx, userID, s.securityPolicy.MaximumAttempts, s.securityPolicy.LockoutDuration,
	)
	if err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	if blocked {
		return domain.ErrAccountLocked
	}
	return failure
}

func (s *Service) validUsername(username string) bool {
	length := len(username)
	return length >= s.registration.MinimumUsernameLength &&
		length <= s.registration.MaximumUsernameLength &&
		safeUsername.MatchString(username)
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func userDTO(value *domain.User) dto.User {
	return dto.User{
		ID: value.ID, Username: value.Username,
		TOTPEnabled: value.TOTPEnabled, RegisteredAt: value.RegisteredAt,
	}
}
