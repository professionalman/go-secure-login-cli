package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/service"
)

type EnableTOTPHandler struct {
	enrollment service.TOTPEnrollmentService
	state      SessionState
	terminal   Terminal
	qr         QRRenderer
}

func NewEnableTOTPHandler(
	enrollment service.TOTPEnrollmentService,
	state SessionState,
	terminal Terminal,
	qr QRRenderer,
) *EnableTOTPHandler {
	return &EnableTOTPHandler{enrollment: enrollment, state: state, terminal: terminal, qr: qr}
}

func (h *EnableTOTPHandler) Handle(ctx context.Context) error {
	rawToken := h.state.SessionToken()
	setup, err := h.enrollment.BeginTOTPSetup(ctx, rawToken)
	if err != nil {
		h.handleSetupError(err, rawToken)
		return nil
	}

	h.terminal.Println("Scan this QR code with your authenticator application:")
	h.qr.Render(setup.ProvisioningURI)
	h.terminal.Println("Provisioning URI: " + setup.ProvisioningURI)
	h.terminal.Println("Issuer: " + setup.Issuer)
	h.terminal.Println("Account: " + setup.AccountName)
	h.terminal.Println(fmt.Sprintf("Code format: %d digits every %d seconds", setup.Digits, setup.Period))
	h.terminal.Println("Setup expires: " + setup.ExpiresAt.UTC().Format(time.RFC3339))

	for {
		code, err := h.terminal.PromptSecret("Current authenticator code (blank to cancel): ")
		if err != nil {
			h.enrollment.CancelTOTPSetup(rawToken)
			return fmt.Errorf("read TOTP confirmation code: %w", err)
		}
		if strings.TrimSpace(code) == "" {
			h.enrollment.CancelTOTPSetup(rawToken)
			h.terminal.Println("Two-factor setup cancelled.")
			return nil
		}

		err = h.enrollment.ConfirmTOTPSetup(ctx, rawToken, code)
		switch {
		case err == nil:
			h.terminal.Println("Two-factor authentication enabled successfully.")
			return nil
		case errors.Is(err, domain.ErrInvalidTOTP):
			h.terminal.Println("Invalid authenticator code. Try again or press Enter to cancel.")
			continue
		case errors.Is(err, domain.ErrTOTPSetupExpired):
			h.terminal.Println("Two-factor setup expired. Start `enable-2fa` again.")
			return nil
		case errors.Is(err, domain.ErrTOTPSetupNotFound):
			h.terminal.Println("No pending two-factor setup was found. Start `enable-2fa` again.")
			return nil
		case errors.Is(err, domain.ErrTOTPAlreadyEnabled):
			h.terminal.Println("Two-factor authentication is already enabled.")
			return nil
		case isInvalidSessionError(err):
			h.enrollment.CancelTOTPSetup(rawToken)
			h.state.ClearSession()
			h.terminal.Println("Your session is no longer valid. Please log in again.")
			return nil
		default:
			h.enrollment.CancelTOTPSetup(rawToken)
			h.terminal.Println("Unable to enable two-factor authentication. Please try again.")
			return nil
		}
	}
}

func (h *EnableTOTPHandler) handleSetupError(err error, rawToken string) {
	switch {
	case errors.Is(err, domain.ErrTOTPAlreadyEnabled):
		h.terminal.Println("Two-factor authentication is already enabled.")
	case isInvalidSessionError(err):
		h.enrollment.CancelTOTPSetup(rawToken)
		h.state.ClearSession()
		h.terminal.Println("Your session is no longer valid. Please log in again.")
	default:
		h.terminal.Println("Unable to start two-factor setup. Please try again.")
	}
}

func isInvalidSessionError(err error) bool {
	return errors.Is(err, domain.ErrSessionExpired) ||
		errors.Is(err, domain.ErrSessionRevoked) ||
		errors.Is(err, domain.ErrUnauthorized)
}
