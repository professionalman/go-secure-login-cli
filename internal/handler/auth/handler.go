package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/handler/shared"
	authservice "auth-cli/internal/service/auth"
)

type Handler struct {
	auth     authservice.IAuthService
	state    shared.ISessionState
	terminal shared.ITerminal
}

func NewHandler(
	auth authservice.IAuthService,
	state shared.ISessionState,
	terminal shared.ITerminal,
) *Handler {
	return &Handler{auth: auth, state: state, terminal: terminal}
}

func (h *Handler) Register(ctx context.Context) error {
	username, err := h.terminal.Prompt("Username: ")
	if err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	password, err := h.terminal.PromptSecret("Password: ")
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	confirmation, err := h.terminal.PromptSecret("Confirm password: ")
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}
	_, err = h.auth.Register(ctx, dto.RegisterInput{
		Username: username, Password: password, PasswordConfirmation: confirmation,
	})
	switch {
	case err == nil:
		h.terminal.Println("User registered successfully.")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		h.terminal.Println("Username already exists.")
	case errors.Is(err, domain.ErrInvalidUsername):
		h.terminal.Println("Username is invalid. Use letters, numbers, dots, underscores, or hyphens.")
	case errors.Is(err, domain.ErrInvalidPassword):
		h.terminal.Println("Password does not meet the configured length requirements.")
	case errors.Is(err, domain.ErrPasswordMismatch):
		h.terminal.Println("Passwords do not match.")
	default:
		h.terminal.Println("Registration failed. Please try again.")
	}
	return nil
}

func (h *Handler) Login(ctx context.Context) error {
	username, err := h.terminal.Prompt("Username: ")
	if err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	password, err := h.terminal.PromptSecret("Password: ")
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	result, err := h.auth.LoginWithPassword(ctx, dto.LoginInput{Username: username, Password: password})
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		h.terminal.Println("Invalid username or password.")
		return nil
	case errors.Is(err, domain.ErrAccountLocked):
		h.terminal.Println("Account temporarily locked. Please try again later.")
		return nil
	case err != nil || result == nil:
		h.terminal.Println("Login failed. Please try again.")
		return nil
	case result.Status == dto.LoginStatusTOTPRequired:
		return h.completeTOTPLogin(ctx, result)
	case result.Status != dto.LoginStatusAuthenticated:
		h.terminal.Println("Login failed. Please try again.")
		return nil
	}
	h.acceptLogin(result)
	return nil
}

func (h *Handler) completeTOTPLogin(ctx context.Context, challenge *dto.LoginResult) error {
	if challenge.ChallengeID == "" {
		h.terminal.Println("Login failed. Please try again.")
		return nil
	}
	h.terminal.Println("Password accepted. Enter your authenticator code to finish login.")
	for {
		code, err := h.terminal.PromptSecret("Authenticator code (blank to cancel): ")
		if err != nil {
			h.auth.CancelTOTPLogin(challenge.ChallengeID)
			return fmt.Errorf("read TOTP login code: %w", err)
		}
		if strings.TrimSpace(code) == "" {
			h.auth.CancelTOTPLogin(challenge.ChallengeID)
			h.terminal.Println("Login cancelled.")
			return nil
		}
		result, err := h.auth.CompleteTOTPLogin(ctx, challenge.ChallengeID, code)
		switch {
		case err == nil && result != nil && result.Status == dto.LoginStatusAuthenticated:
			h.acceptLogin(result)
			return nil
		case errors.Is(err, domain.ErrInvalidTOTP):
			h.terminal.Println("Invalid authenticator code. Try again or press Enter to cancel.")
		case errors.Is(err, domain.ErrAccountLocked):
			h.terminal.Println("Account temporarily locked. Please try again later.")
			return nil
		case errors.Is(err, domain.ErrTOTPChallengeExpired), errors.Is(err, domain.ErrTOTPChallengeNotFound):
			h.terminal.Println("Two-factor login challenge expired. Run `login` again.")
			return nil
		case errors.Is(err, domain.ErrTOTPNotEnabled):
			h.terminal.Println("Two-factor authentication settings changed. Run `login` again.")
			return nil
		default:
			h.auth.CancelTOTPLogin(challenge.ChallengeID)
			h.terminal.Println("Login failed. Please try again.")
			return nil
		}
	}
}

func (h *Handler) acceptLogin(result *dto.LoginResult) {
	h.state.SetSession(result.RawSessionToken)
	h.terminal.Println("Login successful.")
	PrintUserDetails(h.terminal, result.User, result.SessionExpiresAt)
	if result.PreviousLastLogin == nil {
		h.terminal.Println("Previous login: Never")
	} else {
		h.terminal.Println("Previous login: " + result.PreviousLastLogin.UTC().Format(time.RFC3339))
	}
}

func PrintUserDetails(terminal shared.ITerminal, user dto.User, expiresAt time.Time) {
	terminal.Println("Username: " + user.Username)
	terminal.Println("Registration date: " + user.RegisteredAt.UTC().Format(time.RFC3339))
	if user.TOTPEnabled {
		terminal.Println("MFA status: enabled")
	} else {
		terminal.Println("MFA status: disabled")
	}
	terminal.Println("Session expires: " + expiresAt.UTC().Format(time.RFC3339))
}
