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
)

type pendingTOTPLogin struct {
	userID    string
	expiresAt time.Time
}

type pendingTOTPLoginStore struct {
	mu   sync.Mutex
	byID map[string]pendingTOTPLogin
}

type totpLoginDependencies struct {
	totp          TOTPService
	cipher        SecretCipher
	timeout       time.Duration
	generateToken SessionTokenGenerator
	store         *pendingTOTPLoginStore
}

func WithTOTPLogin(
	totpService TOTPService,
	cipher SecretCipher,
	timeout time.Duration,
	generateToken SessionTokenGenerator,
) AuthOption {
	return func(service *DefaultAuthService) {
		service.totpLogin = &totpLoginDependencies{
			totp: totpService, cipher: cipher, timeout: timeout, generateToken: generateToken,
			store: &pendingTOTPLoginStore{byID: make(map[string]pendingTOTPLogin)},
		}
	}
}

func (s *DefaultAuthService) beginTOTPLogin(userID string, now time.Time) (*dto.LoginResult, error) {
	if s.totpLogin == nil || s.totpLogin.generateToken == nil {
		return nil, errors.New("TOTP login is not configured")
	}
	challengeID, _, err := s.totpLogin.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate TOTP login challenge: %w", err)
	}
	if challengeID == "" {
		return nil, errors.New("generated an empty TOTP login challenge")
	}
	expiresAt := now.Add(s.totpLogin.timeout)
	store := s.totpLogin.store
	store.mu.Lock()
	defer store.mu.Unlock()
	removeExpiredTOTPLogins(store, now)
	if _, exists := store.byID[challengeID]; exists {
		return nil, errors.New("generated a duplicate TOTP login challenge")
	}
	store.byID[challengeID] = pendingTOTPLogin{userID: userID, expiresAt: expiresAt}
	return &dto.LoginResult{
		Status:             dto.LoginStatusTOTPRequired,
		ChallengeID:        challengeID,
		ChallengeExpiresAt: expiresAt,
	}, nil
}

func (s *DefaultAuthService) CompleteTOTPLogin(
	ctx context.Context,
	challengeID string,
	code string,
) (*dto.LoginResult, error) {
	if s.totpLogin == nil || s.sessions == nil {
		return nil, errors.New("TOTP login is not configured")
	}
	store := s.totpLogin.store
	store.mu.Lock()
	defer store.mu.Unlock()

	challenge, found := store.byID[challengeID]
	if !found {
		return nil, domain.ErrTOTPChallengeNotFound
	}
	now := s.clock.Now().UTC()
	if !now.Before(challenge.expiresAt) {
		delete(store.byID, challengeID)
		return nil, domain.ErrTOTPChallengeExpired
	}

	user, err := s.users.FindByID(ctx, challenge.userID)
	if errors.Is(err, repository.ErrNotFound) {
		delete(store.byID, challengeID)
		return nil, domain.ErrTOTPChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find TOTP login user: %w", err)
	}
	if isLoginLocked(user, now) {
		delete(store.byID, challengeID)
		return nil, domain.ErrAccountLocked
	}
	if !user.TOTPEnabled || user.TOTPSecretEncrypted == nil {
		delete(store.byID, challengeID)
		return nil, domain.ErrTOTPNotEnabled
	}

	secret, err := s.totpLogin.cipher.Decrypt(*user.TOTPSecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt TOTP login secret: %w", err)
	}
	valid, err := s.totpLogin.totp.Validate(secret, code)
	if err != nil {
		return nil, fmt.Errorf("validate TOTP login code: %w", err)
	}
	if !valid {
		if err := s.recordFailedLogin(ctx, user, now); err != nil {
			if errors.Is(err, domain.ErrAccountLocked) {
				delete(store.byID, challengeID)
				return nil, domain.ErrAccountLocked
			}
			return nil, fmt.Errorf("record failed TOTP login: %w", err)
		}
		return nil, domain.ErrInvalidTOTP
	}

	session, err := s.sessions.FinalizeLogin(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("finalize TOTP login: %w", err)
	}
	delete(store.byID, challengeID)
	return authenticatedLoginResult(session), nil
}

func (s *DefaultAuthService) CancelTOTPLogin(challengeID string) {
	if s.totpLogin == nil {
		return
	}
	store := s.totpLogin.store
	store.mu.Lock()
	delete(store.byID, challengeID)
	store.mu.Unlock()
}

func (s *DefaultAuthService) ClearTOTPLoginChallenges() {
	if s.totpLogin == nil {
		return
	}
	store := s.totpLogin.store
	store.mu.Lock()
	store.byID = make(map[string]pendingTOTPLogin)
	store.mu.Unlock()
}

func removeExpiredTOTPLogins(store *pendingTOTPLoginStore, now time.Time) {
	for challengeID, challenge := range store.byID {
		if !now.Before(challenge.expiresAt) {
			delete(store.byID, challengeID)
		}
	}
}
