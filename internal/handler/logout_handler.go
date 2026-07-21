package handler

import (
	"context"
	"errors"

	"auth-cli/internal/domain"
	"auth-cli/internal/service"
)

type LogoutHandler struct {
	sessions service.SessionService
	state    SessionState
	terminal Terminal
}

func NewLogoutHandler(sessions service.SessionService, state SessionState, terminal Terminal) *LogoutHandler {
	return &LogoutHandler{sessions: sessions, state: state, terminal: terminal}
}

func (h *LogoutHandler) Handle(ctx context.Context) {
	err := h.sessions.Logout(ctx, h.state.SessionToken())
	if err == nil {
		h.state.ClearSession()
		h.terminal.Println("Logged out successfully.")
		return
	}
	if errors.Is(err, domain.ErrSessionExpired) || errors.Is(err, domain.ErrSessionRevoked) || errors.Is(err, domain.ErrUnauthorized) {
		h.state.ClearSession()
		h.terminal.Println("Your session is no longer valid. Please log in again.")
		return
	}
	h.terminal.Println("Logout failed. Please try again.")
}
