package handler

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
)

type fakeLoginService struct {
	result *dto.LoginResult
	err    error
	input  dto.LoginInput
}

func (f *fakeLoginService) LoginWithPassword(_ context.Context, input dto.LoginInput) (*dto.LoginResult, error) {
	f.input = input
	return f.result, f.err
}

type fakeSessionState struct{ token string }

func (f *fakeSessionState) SessionToken() string    { return f.token }
func (f *fakeSessionState) SetSession(token string) { f.token = token }
func (f *fakeSessionState) ClearSession()           { f.token = "" }

type fakeSessionService struct {
	validated      *dto.AuthenticatedUser
	validateErr    error
	logoutErr      error
	validatedToken string
	logoutToken    string
}

func (f *fakeSessionService) FinalizeLogin(context.Context, string) (*dto.SessionResult, error) {
	return nil, errors.New("not used")
}
func (f *fakeSessionService) ValidateSession(_ context.Context, token string) (*dto.AuthenticatedUser, error) {
	f.validatedToken = token
	return f.validated, f.validateErr
}
func (f *fakeSessionService) Logout(_ context.Context, token string) error {
	f.logoutToken = token
	return f.logoutErr
}

func TestLoginHandlerSuccessAndInvalidCredentials(t *testing.T) {
	now := time.Date(2026, time.July, 21, 18, 0, 0, 0, time.UTC)
	auth := &fakeLoginService{result: &dto.LoginResult{
		Status:          dto.LoginStatusAuthenticated,
		User:            dto.User{Username: "alice", RegisteredAt: now.Add(-time.Hour)},
		RawSessionToken: "raw-token", SessionExpiresAt: now.Add(30 * time.Minute),
	}}
	state := &fakeSessionState{}
	terminal := &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password"}}
	handler := NewLoginHandler(auth, state, terminal)
	if err := handler.Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state.token != "raw-token" {
		t.Errorf("state token = %q", state.token)
	}
	if !slices.Contains(terminal.messages, "Login successful.") || !slices.Contains(terminal.messages, "Username: alice") {
		t.Errorf("messages = %v", terminal.messages)
	}

	auth.err = domain.ErrInvalidCredentials
	auth.result = nil
	terminal = &fakeTerminal{responses: []string{"alice"}, secrets: []string{"wrong"}}
	handler = NewLoginHandler(auth, &fakeSessionState{}, terminal)
	if err := handler.Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(terminal.messages, []string{"Invalid username or password."}) {
		t.Errorf("messages = %v", terminal.messages)
	}
}

func TestWhoAmIAndLogoutStateTransitions(t *testing.T) {
	now := time.Now().UTC()
	sessions := &fakeSessionService{validated: &dto.AuthenticatedUser{
		User: dto.User{Username: "alice", RegisteredAt: now}, ExpiresAt: now.Add(time.Minute),
	}}
	state := &fakeSessionState{token: "raw"}
	terminal := &fakeTerminal{}
	NewWhoAmIHandler(sessions, state, terminal).Handle(context.Background())
	if sessions.validatedToken != "raw" || !slices.Contains(terminal.messages, "Username: alice") {
		t.Errorf("whoami state/messages = %q/%v", sessions.validatedToken, terminal.messages)
	}

	terminal.messages = nil
	NewLogoutHandler(sessions, state, terminal).Handle(context.Background())
	if state.token != "" || sessions.logoutToken != "raw" {
		t.Errorf("logout state/token = %q/%q", state.token, sessions.logoutToken)
	}
	if !slices.Equal(terminal.messages, []string{"Logged out successfully."}) {
		t.Errorf("messages = %v", terminal.messages)
	}
}

func TestExpiredWhoAmIClearsState(t *testing.T) {
	sessions := &fakeSessionService{validateErr: domain.ErrSessionExpired}
	state := &fakeSessionState{token: "raw"}
	terminal := &fakeTerminal{}
	NewWhoAmIHandler(sessions, state, terminal).Handle(context.Background())
	if state.token != "" {
		t.Fatal("expired session token remained in state")
	}
	if !slices.Equal(terminal.messages, []string{"Your session has expired. Please log in again."}) {
		t.Errorf("messages = %v", terminal.messages)
	}
}
