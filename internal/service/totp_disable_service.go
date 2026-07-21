package service

import (
	"context"
	"errors"
	"fmt"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"
)

type TOTPDisableService interface {
	DisableTOTP(ctx context.Context, rawSessionToken, password, code string) error
}

func (s *DefaultAuthService) DisableTOTP(
	ctx context.Context,
	rawSessionToken string,
	password string,
	code string,
) error {
	if s.totpEnrollment == nil || s.sessions == nil || s.verifier == nil {
		return errors.New("TOTP disable flow is not configured")
	}
	authenticated, err := s.sessions.ValidateSession(ctx, rawSessionToken)
	if err != nil {
		return err
	}
	user, err := s.users.FindByID(ctx, authenticated.User.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return domain.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("find TOTP disable user: %w", err)
	}
	if !user.TOTPEnabled || user.TOTPSecretEncrypted == nil {
		return domain.ErrTOTPNotEnabled
	}
	if err := s.verifier.Verify(user.PasswordHash, password); err != nil {
		return domain.ErrInvalidCredentials
	}
	secret, err := s.totpEnrollment.cipher.Decrypt(*user.TOTPSecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt TOTP disable secret: %w", err)
	}
	valid, err := s.totpEnrollment.totp.Validate(secret, code)
	if err != nil {
		return fmt.Errorf("validate TOTP disable code: %w", err)
	}
	if !valid {
		return domain.ErrInvalidTOTP
	}
	if err := s.users.DisableTOTP(ctx, user.ID, s.clock.Now().UTC()); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return domain.ErrTOTPNotEnabled
		}
		return fmt.Errorf("persist disabled TOTP: %w", err)
	}
	return nil
}
