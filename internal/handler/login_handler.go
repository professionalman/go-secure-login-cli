package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/service"
)

type LoginHandler struct {
	auth     service.LoginService
	state    SessionState
	terminal Terminal
}

func NewLoginHandler(auth service.LoginService, state SessionState, terminal Terminal) *LoginHandler {
	return &LoginHandler{auth: auth, state: state, terminal: terminal}
}

func (h *LoginHandler) Handle(ctx context.Context) error {
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
	case err != nil:
		h.terminal.Println("Login failed. Please try again.")
		return nil
	case result.Status == dto.LoginStatusTOTPRequired:
		h.terminal.Println("Two-factor login is not available until its milestone is implemented.")
		return nil
	case result.Status != dto.LoginStatusAuthenticated:
		h.terminal.Println("Login failed. Please try again.")
		return nil
	}

	h.state.SetSession(result.RawSessionToken)
	h.terminal.Println("Login successful.")
	printUserDetails(h.terminal, result.User, result.SessionExpiresAt)
	if result.PreviousLastLogin == nil {
		h.terminal.Println("Previous login: Never")
	} else {
		h.terminal.Println("Previous login: " + result.PreviousLastLogin.UTC().Format(time.RFC3339))
	}
	return nil
}

func printUserDetails(terminal Terminal, user dto.User, expiresAt time.Time) {
	terminal.Println("Username: " + user.Username)
	terminal.Println("Registration date: " + user.RegisteredAt.UTC().Format(time.RFC3339))
	if user.TOTPEnabled {
		terminal.Println("MFA status: enabled")
	} else {
		terminal.Println("MFA status: disabled")
	}
	terminal.Println("Session expires: " + expiresAt.UTC().Format(time.RFC3339))
}
