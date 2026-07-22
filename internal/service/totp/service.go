package totp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
	userrepository "auth-cli/internal/repository/user"
	"auth-cli/internal/security"
	sessionservice "auth-cli/internal/service/session"

	"github.com/pquerna/otp"
	otplib "github.com/pquerna/otp/totp"
)

type Policy struct {
	Issuer string
	Period uint
	Skew   uint
	Digits int
}

type pendingSetup struct {
	userID      string
	secret      string
	expiresAt   time.Time
	sessionHash string
}

type Option func(*Service)

func WithRandomReader(reader io.Reader) Option {
	return func(service *Service) { service.random = reader }
}

type Service struct {
	users        userrepository.IUserRepository
	sessions     sessionservice.ISessionService
	passwords    security.IPasswordManager
	cipher       ISecretCipher
	policy       Policy
	setupTimeout time.Duration
	random       io.Reader
	mu           sync.Mutex
	byUser       map[string]pendingSetup
	bySession    map[string]string
}

func NewService(
	users userrepository.IUserRepository,
	sessions sessionservice.ISessionService,
	passwords security.IPasswordManager,
	cipher ISecretCipher,
	policy Policy,
	setupTimeout time.Duration,
	options ...Option,
) *Service {
	service := &Service{
		users: users, sessions: sessions, passwords: passwords, cipher: cipher,
		policy: policy, setupTimeout: setupTimeout,
		byUser: make(map[string]pendingSetup), bySession: make(map[string]string),
	}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) BeginSetup(ctx context.Context, rawSessionToken string) (*dto.TOTPSetupResult, error) {
	authenticated, err := s.sessions.ValidateSession(ctx, rawSessionToken)
	if err != nil {
		return nil, err
	}
	if authenticated.User.TOTPEnabled {
		return nil, domain.ErrTOTPAlreadyEnabled
	}
	key, err := otplib.Generate(otplib.GenerateOpts{
		Issuer: s.policy.Issuer, AccountName: authenticated.User.Username,
		Period: s.policy.Period, Digits: otp.Digits(s.policy.Digits),
		Algorithm: otp.AlgorithmSHA1, Rand: s.random,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP provisioning data: %w", err)
	}
	now := time.Now().UTC()
	value := pendingSetup{
		userID: authenticated.User.ID, secret: key.Secret(),
		expiresAt:   now.Add(s.setupTimeout),
		sessionHash: security.HashSessionToken(rawSessionToken),
	}
	s.mu.Lock()
	if previous, found := s.byUser[value.userID]; found {
		delete(s.bySession, previous.sessionHash)
	}
	s.byUser[value.userID] = value
	s.bySession[value.sessionHash] = value.userID
	s.mu.Unlock()
	return &dto.TOTPSetupResult{
		ProvisioningURI: key.URL(), Issuer: s.policy.Issuer,
		AccountName: authenticated.User.Username, Period: s.policy.Period,
		Digits: s.policy.Digits, ExpiresAt: value.expiresAt,
	}, nil
}

func (s *Service) ConfirmSetup(ctx context.Context, rawSessionToken, code string) error {
	authenticated, err := s.sessions.ValidateSession(ctx, rawSessionToken)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.byUser[authenticated.User.ID]
	if !found {
		return domain.ErrTOTPSetupNotFound
	}
	if !time.Now().UTC().Before(value.expiresAt) {
		s.removeSetup(value)
		return domain.ErrTOTPSetupExpired
	}
	if authenticated.User.TOTPEnabled {
		s.removeSetup(value)
		return domain.ErrTOTPAlreadyEnabled
	}
	valid, err := s.validateCode(value.secret, code)
	if err != nil {
		return fmt.Errorf("confirm TOTP code: %w", err)
	}
	if !valid {
		return domain.ErrInvalidTOTP
	}
	encrypted, err := s.cipher.Encrypt(value.secret)
	if err != nil {
		return fmt.Errorf("encrypt TOTP secret: %w", err)
	}
	if err := s.users.EnableTOTP(ctx, value.userID, encrypted, time.Now().UTC()); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			s.removeSetup(value)
			return domain.ErrTOTPAlreadyEnabled
		}
		return fmt.Errorf("persist TOTP enrollment: %w", err)
	}
	s.removeSetup(value)
	return nil
}

func (s *Service) CancelSetup(rawSessionToken string) {
	hash := security.HashSessionToken(rawSessionToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, found := s.bySession[hash]
	if !found {
		return
	}
	value, found := s.byUser[userID]
	if found && value.sessionHash == hash {
		s.removeSetup(value)
	}
}

func (s *Service) ClearPendingSetups() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byUser = make(map[string]pendingSetup)
	s.bySession = make(map[string]string)
}

func (s *Service) ValidateEncryptedCode(encryptedSecret, code string) (bool, error) {
	secret, err := s.cipher.Decrypt(encryptedSecret)
	if err != nil {
		return false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	return s.validateCode(secret, code)
}

func (s *Service) Disable(ctx context.Context, rawSessionToken, password, code string) error {
	authenticated, err := s.sessions.ValidateSession(ctx, rawSessionToken)
	if err != nil {
		return err
	}
	user, err := s.users.FindByID(ctx, authenticated.User.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return domain.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("find TOTP user: %w", err)
	}
	if !user.TOTPEnabled || user.TOTPSecretEncrypted == nil {
		return domain.ErrTOTPNotEnabled
	}
	if err := s.passwords.Verify(user.PasswordHash, password); err != nil {
		return domain.ErrInvalidCredentials
	}
	valid, err := s.ValidateEncryptedCode(*user.TOTPSecretEncrypted, code)
	if err != nil {
		return fmt.Errorf("validate disable TOTP code: %w", err)
	}
	if !valid {
		return domain.ErrInvalidTOTP
	}
	if err := s.users.DisableTOTP(ctx, user.ID, time.Now().UTC()); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return domain.ErrTOTPNotEnabled
		}
		return fmt.Errorf("disable TOTP: %w", err)
	}
	return nil
}

func (s *Service) validateCode(secret, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if len(code) != s.policy.Digits {
		return false, nil
	}
	for _, character := range code {
		if character > unicode.MaxASCII || !unicode.IsDigit(character) {
			return false, nil
		}
	}
	valid, err := otplib.ValidateCustom(code, secret, time.Now().UTC(), otplib.ValidateOpts{
		Period: s.policy.Period, Skew: s.policy.Skew,
		Digits: otp.Digits(s.policy.Digits), Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false, fmt.Errorf("validate TOTP code: %w", err)
	}
	return valid, nil
}

func (s *Service) removeSetup(value pendingSetup) {
	delete(s.byUser, value.userID)
	delete(s.bySession, value.sessionHash)
}
