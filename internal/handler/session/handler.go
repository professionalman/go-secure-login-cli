package session

import (
	"context"
	"errors"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/handler/shared"
	sessionservice "auth-cli/internal/service/session"
)

type Handler struct {
	sessions sessionservice.ISessionService
	state    shared.ISessionState
	terminal shared.ITerminal
}

func NewHandler(
	sessions sessionservice.ISessionService,
	state shared.ISessionState,
	terminal shared.ITerminal,
) *Handler {
	return &Handler{sessions: sessions, state: state, terminal: terminal}
}

func (h *Handler) WhoAmI(ctx context.Context) {
	user, err := h.sessions.ValidateSession(ctx, h.state.SessionToken())
	if errors.Is(err, domain.ErrSessionExpired) {
		h.state.ClearSession()
		h.terminal.Println("Your session has expired. Please log in again.")
		return
	}
	if errors.Is(err, domain.ErrSessionRevoked) || errors.Is(err, domain.ErrUnauthorized) {
		h.state.ClearSession()
		h.terminal.Println("Your session is no longer valid. Please log in again.")
		return
	}
	if err != nil {
		h.terminal.Println("Unable to validate your session. Please try again.")
		return
	}
	printUserDetails(h.terminal, user.User, user.ExpiresAt)
}

func (h *Handler) Logout(ctx context.Context) {
	rawToken := h.state.SessionToken()
	defer h.state.ClearSession()
	err := h.sessions.Logout(ctx, rawToken)
	switch {
	case err == nil:
		h.terminal.Println("Logged out successfully.")
	case errors.Is(err, domain.ErrSessionExpired),
		errors.Is(err, domain.ErrSessionRevoked),
		errors.Is(err, domain.ErrUnauthorized):
		h.terminal.Println("Your session is no longer valid. Local session cleared.")
	default:
		h.terminal.Println("Local session cleared, but server logout failed.")
	}
}

func printUserDetails(terminal shared.ITerminal, user dto.User, expiresAt time.Time) {
	terminal.Println("Username: " + user.Username)
	terminal.Println("Registration date: " + user.RegisteredAt.UTC().Format(time.RFC3339))
	if user.TOTPEnabled {
		terminal.Println("MFA status: enabled")
	} else {
		terminal.Println("MFA status: disabled")
	}
	terminal.Println("Session expires: " + expiresAt.UTC().Format(time.RFC3339))
}
