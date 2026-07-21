package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"auth-cli/internal/domain"
	"auth-cli/internal/service"
)

type DisableTOTPHandler struct {
	auth     service.TOTPDisableService
	state    SessionState
	terminal Terminal
}

func NewDisableTOTPHandler(
	auth service.TOTPDisableService,
	state SessionState,
	terminal Terminal,
) *DisableTOTPHandler {
	return &DisableTOTPHandler{auth: auth, state: state, terminal: terminal}
}

func (h *DisableTOTPHandler) Handle(ctx context.Context) error {
	password, err := h.terminal.PromptSecret("Current password: ")
	if err != nil {
		return fmt.Errorf("read current password: %w", err)
	}
	code, err := h.terminal.PromptSecret("Current authenticator code (blank to cancel): ")
	if err != nil {
		return fmt.Errorf("read TOTP disable code: %w", err)
	}
	if strings.TrimSpace(code) == "" {
		h.terminal.Println("Disable two-factor authentication cancelled.")
		return nil
	}

	err = h.auth.DisableTOTP(ctx, h.state.SessionToken(), password, code)
	switch {
	case err == nil:
		h.terminal.Println("Two-factor authentication disabled successfully.")
	case errors.Is(err, domain.ErrInvalidCredentials):
		h.terminal.Println("Current password is incorrect.")
	case errors.Is(err, domain.ErrInvalidTOTP):
		h.terminal.Println("Invalid authenticator code.")
	case errors.Is(err, domain.ErrTOTPNotEnabled):
		h.terminal.Println("Two-factor authentication is not enabled.")
	case isInvalidSessionError(err):
		h.state.ClearSession()
		h.terminal.Println("Your session is no longer valid. Please log in again.")
	default:
		h.terminal.Println("Unable to disable two-factor authentication. Please try again.")
	}
	return nil
}
