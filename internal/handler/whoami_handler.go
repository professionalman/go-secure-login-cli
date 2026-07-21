package handler

import (
	"context"
	"errors"

	"auth-cli/internal/domain"
	"auth-cli/internal/service"
)

type WhoAmIHandler struct {
	sessions service.SessionService
	state    SessionState
	terminal Terminal
}

func NewWhoAmIHandler(sessions service.SessionService, state SessionState, terminal Terminal) *WhoAmIHandler {
	return &WhoAmIHandler{sessions: sessions, state: state, terminal: terminal}
}

func (h *WhoAmIHandler) Handle(ctx context.Context) {
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
