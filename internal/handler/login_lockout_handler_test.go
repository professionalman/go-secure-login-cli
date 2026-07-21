package handler

import (
	"context"
	"slices"
	"testing"

	"auth-cli/internal/domain"
)

func TestLoginHandlerMapsAccountLockout(t *testing.T) {
	auth := &fakeLoginService{err: domain.ErrAccountLocked}
	state := &fakeSessionState{}
	terminal := &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password"}}

	if err := NewLoginHandler(auth, state, terminal).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(terminal.messages, []string{"Account temporarily locked. Please try again later."}) {
		t.Fatalf("messages = %v", terminal.messages)
	}
	if state.token != "" {
		t.Fatalf("lockout authenticated the CLI with token %q", state.token)
	}
}
