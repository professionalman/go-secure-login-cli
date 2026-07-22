package totp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/handler/shared"
	totpservice "auth-cli/internal/service/totp"
)

type Handler struct {
	totp     totpservice.ITOTPService
	state    shared.ISessionState
	terminal shared.ITerminal
	qr       shared.IQRRenderer
}

func NewHandler(
	totp totpservice.ITOTPService,
	state shared.ISessionState,
	terminal shared.ITerminal,
	qr shared.IQRRenderer,
) *Handler {
	return &Handler{totp: totp, state: state, terminal: terminal, qr: qr}
}

func (h *Handler) Enable(ctx context.Context) error {
	rawToken := h.state.SessionToken()
	setup, err := h.totp.BeginSetup(ctx, rawToken)
	if err != nil {
		h.handleSetupError(err)
		return nil
	}
	h.terminal.Println("Scan this QR code with your authenticator application:")
	h.qr.Render(setup.ProvisioningURI)
	h.terminal.Println("Provisioning URI: " + setup.ProvisioningURI)
	h.terminal.Println("Setup expires: " + setup.ExpiresAt.UTC().Format(time.RFC3339))
	for {
		code, err := h.terminal.PromptSecret("Authenticator code (blank to cancel): ")
		if err != nil {
			h.totp.CancelSetup(rawToken)
			return fmt.Errorf("read TOTP setup code: %w", err)
		}
		if strings.TrimSpace(code) == "" {
			h.totp.CancelSetup(rawToken)
			h.terminal.Println("Two-factor setup cancelled.")
			return nil
		}
		err = h.totp.ConfirmSetup(ctx, rawToken, code)
		switch {
		case err == nil:
			h.terminal.Println("Two-factor authentication enabled.")
			return nil
		case errors.Is(err, domain.ErrInvalidTOTP):
			h.terminal.Println("Invalid authenticator code. Try again or press Enter to cancel.")
		case errors.Is(err, domain.ErrTOTPSetupExpired), errors.Is(err, domain.ErrTOTPSetupNotFound):
			h.terminal.Println("Two-factor setup expired. Run `enable-2fa` again.")
			return nil
		default:
			h.handleSetupError(err)
			return nil
		}
	}
}

func (h *Handler) Disable(ctx context.Context) error {
	password, err := h.terminal.PromptSecret("Current password (blank to cancel): ")
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	if password == "" {
		h.terminal.Println("Disable two-factor authentication cancelled.")
		return nil
	}
	code, err := h.terminal.PromptSecret("Authenticator code (blank to cancel): ")
	if err != nil {
		return fmt.Errorf("read TOTP code: %w", err)
	}
	if strings.TrimSpace(code) == "" {
		h.terminal.Println("Disable two-factor authentication cancelled.")
		return nil
	}
	err = h.totp.Disable(ctx, h.state.SessionToken(), password, code)
	switch {
	case err == nil:
		h.terminal.Println("Two-factor authentication disabled.")
	case errors.Is(err, domain.ErrInvalidCredentials):
		h.terminal.Println("Current password is incorrect.")
	case errors.Is(err, domain.ErrInvalidTOTP):
		h.terminal.Println("Authenticator code is invalid.")
	case errors.Is(err, domain.ErrTOTPNotEnabled):
		h.terminal.Println("Two-factor authentication is not enabled.")
	case errors.Is(err, domain.ErrSessionExpired),
		errors.Is(err, domain.ErrSessionRevoked),
		errors.Is(err, domain.ErrUnauthorized):
		h.state.ClearSession()
		h.terminal.Println("Your session is no longer valid. Please log in again.")
	default:
		h.terminal.Println("Unable to disable two-factor authentication. Please try again.")
	}
	return nil
}

func (h *Handler) handleSetupError(err error) {
	switch {
	case errors.Is(err, domain.ErrTOTPAlreadyEnabled):
		h.terminal.Println("Two-factor authentication is already enabled.")
	case errors.Is(err, domain.ErrSessionExpired),
		errors.Is(err, domain.ErrSessionRevoked),
		errors.Is(err, domain.ErrUnauthorized):
		h.state.ClearSession()
		h.terminal.Println("Your session is no longer valid. Please log in again.")
	default:
		h.terminal.Println("Unable to configure two-factor authentication. Please try again.")
	}
}
