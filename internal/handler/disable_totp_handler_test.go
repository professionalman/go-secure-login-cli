package handler

import (
	"context"
	"slices"
	"testing"

	"auth-cli/internal/domain"
)

type fakeDisableTOTPService struct {
	token    string
	password string
	code     string
	err      error
}

func (f *fakeDisableTOTPService) DisableTOTP(_ context.Context, token, password, code string) error {
	f.token, f.password, f.code = token, password, code
	return f.err
}

func TestDisableTOTPHandlerUsesHiddenReauthenticationAndKeepsSession(t *testing.T) {
	auth := &fakeDisableTOTPService{}
	state := &fakeSessionState{token: "raw-session"}
	terminal := &fakeTerminal{secrets: []string{"password", "123456"}}

	if err := NewDisableTOTPHandler(auth, state, terminal).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth.token != "raw-session" || auth.password != "password" || auth.code != "123456" {
		t.Fatalf("service input = %q/%q/%q", auth.token, auth.password, auth.code)
	}
	if terminal.secretCalls != 2 || state.token != "raw-session" {
		t.Fatalf("secret calls/session = %d/%q", terminal.secretCalls, state.token)
	}
	if !slices.Equal(terminal.messages, []string{"Two-factor authentication disabled successfully."}) {
		t.Fatalf("messages = %v", terminal.messages)
	}
}

func TestDisableTOTPHandlerMapsErrorsAndClearsInvalidSession(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		message     string
		clearsState bool
	}{
		{name: "password", err: domain.ErrInvalidCredentials, message: "Current password is incorrect."},
		{name: "code", err: domain.ErrInvalidTOTP, message: "Invalid authenticator code."},
		{name: "disabled", err: domain.ErrTOTPNotEnabled, message: "Two-factor authentication is not enabled."},
		{name: "session", err: domain.ErrSessionExpired, message: "Your session is no longer valid. Please log in again.", clearsState: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &fakeSessionState{token: "raw"}
			terminal := &fakeTerminal{secrets: []string{"password", "123456"}}
			if err := NewDisableTOTPHandler(&fakeDisableTOTPService{err: tt.err}, state, terminal).Handle(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(terminal.messages, []string{tt.message}) {
				t.Fatalf("messages = %v", terminal.messages)
			}
			if (state.token == "") != tt.clearsState {
				t.Fatalf("session token after error = %q", state.token)
			}
		})
	}
}

func TestDisableTOTPHandlerCancelsBlankCode(t *testing.T) {
	auth := &fakeDisableTOTPService{}
	terminal := &fakeTerminal{secrets: []string{"password", ""}}
	if err := NewDisableTOTPHandler(auth, &fakeSessionState{token: "raw"}, terminal).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth.token != "" || !slices.Equal(terminal.messages, []string{"Disable two-factor authentication cancelled."}) {
		t.Fatalf("service token/messages = %q/%v", auth.token, terminal.messages)
	}
}
