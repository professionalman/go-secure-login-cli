package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
	"auth-cli/internal/security"
)

type TOTPEnrollmentService interface {
	BeginTOTPSetup(ctx context.Context, rawSessionToken string) (*dto.TOTPSetupResult, error)
	ConfirmTOTPSetup(ctx context.Context, rawSessionToken, code string) error
	CancelTOTPSetup(rawSessionToken string)
	ClearPendingTOTPSetups()
}

type SecretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

type pendingTOTPSetup struct {
	userID      string
	secret      string
	expiresAt   time.Time
	sessionHash string
}

type pendingTOTPStore struct {
	mu        sync.Mutex
	byUser    map[string]pendingTOTPSetup
	bySession map[string]string
}

type totpEnrollmentDependencies struct {
	totp         TOTPService
	cipher       SecretCipher
	setupTimeout time.Duration
	store        *pendingTOTPStore
}

func WithTOTPEnrollment(totpService TOTPService, cipher SecretCipher, setupTimeout time.Duration) AuthOption {
	return func(service *DefaultAuthService) {
		service.totpEnrollment = &totpEnrollmentDependencies{
			totp: totpService, cipher: cipher, setupTimeout: setupTimeout,
			store: &pendingTOTPStore{
				byUser: make(map[string]pendingTOTPSetup), bySession: make(map[string]string),
			},
		}
	}
}

func (s *DefaultAuthService) BeginTOTPSetup(ctx context.Context, rawSessionToken string) (*dto.TOTPSetupResult, error) {
	if s.totpEnrollment == nil || s.sessions == nil {
		return nil, errors.New("TOTP enrollment is not configured")
	}
	authenticated, err := s.sessions.ValidateSession(ctx, rawSessionToken)
	if err != nil {
		return nil, err
	}
	if authenticated.User.TOTPEnabled {
		return nil, domain.ErrTOTPAlreadyEnabled
	}

	provisioning, err := s.totpEnrollment.totp.Generate(authenticated.User.Username)
	if err != nil {
		return nil, fmt.Errorf("begin TOTP provisioning: %w", err)
	}
	now := s.clock.Now().UTC()
	expiresAt := now.Add(s.totpEnrollment.setupTimeout)
	sessionHash := security.HashSessionToken(rawSessionToken)
	setup := pendingTOTPSetup{
		userID: authenticated.User.ID, secret: provisioning.Secret,
		expiresAt: expiresAt, sessionHash: sessionHash,
	}

	store := s.totpEnrollment.store
	store.mu.Lock()
	if previous, found := store.byUser[setup.userID]; found {
		delete(store.bySession, previous.sessionHash)
	}
	store.byUser[setup.userID] = setup
	store.bySession[sessionHash] = setup.userID
	store.mu.Unlock()

	return &dto.TOTPSetupResult{
		ProvisioningURI: provisioning.ProvisioningURI,
		Issuer:          provisioning.Issuer,
		AccountName:     provisioning.AccountName,
		Period:          provisioning.Period,
		Digits:          provisioning.Digits,
		ExpiresAt:       expiresAt,
	}, nil
}

func (s *DefaultAuthService) ConfirmTOTPSetup(ctx context.Context, rawSessionToken, code string) error {
	if s.totpEnrollment == nil || s.sessions == nil {
		return errors.New("TOTP enrollment is not configured")
	}
	authenticated, err := s.sessions.ValidateSession(ctx, rawSessionToken)
	if err != nil {
		return err
	}

	store := s.totpEnrollment.store
	store.mu.Lock()
	defer store.mu.Unlock()
	setup, found := store.byUser[authenticated.User.ID]
	if !found {
		return domain.ErrTOTPSetupNotFound
	}
	if !s.clock.Now().UTC().Before(setup.expiresAt) {
		removePendingTOTPSetup(store, setup)
		return domain.ErrTOTPSetupExpired
	}
	if authenticated.User.TOTPEnabled {
		removePendingTOTPSetup(store, setup)
		return domain.ErrTOTPAlreadyEnabled
	}

	valid, err := s.totpEnrollment.totp.Validate(setup.secret, code)
	if err != nil {
		return fmt.Errorf("confirm TOTP code: %w", err)
	}
	if !valid {
		return domain.ErrInvalidTOTP
	}
	encryptedSecret, err := s.totpEnrollment.cipher.Encrypt(setup.secret)
	if err != nil {
		return fmt.Errorf("encrypt TOTP secret: %w", err)
	}
	if err := s.users.EnableTOTP(ctx, setup.userID, encryptedSecret, s.clock.Now().UTC()); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			removePendingTOTPSetup(store, setup)
			return domain.ErrTOTPAlreadyEnabled
		}
		return fmt.Errorf("persist TOTP enrollment: %w", err)
	}
	removePendingTOTPSetup(store, setup)
	return nil
}

func (s *DefaultAuthService) CancelTOTPSetup(rawSessionToken string) {
	if s.totpEnrollment == nil {
		return
	}
	store := s.totpEnrollment.store
	store.mu.Lock()
	defer store.mu.Unlock()
	sessionHash := security.HashSessionToken(rawSessionToken)
	userID, found := store.bySession[sessionHash]
	if !found {
		return
	}
	setup, found := store.byUser[userID]
	if found && setup.sessionHash == sessionHash {
		removePendingTOTPSetup(store, setup)
	}
}

func (s *DefaultAuthService) ClearPendingTOTPSetups() {
	if s.totpEnrollment == nil {
		return
	}
	store := s.totpEnrollment.store
	store.mu.Lock()
	defer store.mu.Unlock()
	store.byUser = make(map[string]pendingTOTPSetup)
	store.bySession = make(map[string]string)
}

func removePendingTOTPSetup(store *pendingTOTPStore, setup pendingTOTPSetup) {
	delete(store.byUser, setup.userID)
	delete(store.bySession, setup.sessionHash)
}
