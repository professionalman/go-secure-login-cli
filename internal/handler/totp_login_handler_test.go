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

type fakeTOTPLoginService struct {
	passwordResult *dto.LoginResult
	passwordErr    error
	completeResult *dto.LoginResult
	completeErrs   []error
	codes          []string
	cancelled      string
	cleared        bool
}

func (f *fakeTOTPLoginService) LoginWithPassword(context.Context, dto.LoginInput) (*dto.LoginResult, error) {
	return f.passwordResult, f.passwordErr
}

func (f *fakeTOTPLoginService) CompleteTOTPLogin(_ context.Context, challengeID, code string) (*dto.LoginResult, error) {
	f.codes = append(f.codes, challengeID+":"+code)
	if len(f.completeErrs) > 0 {
		err := f.completeErrs[0]
		f.completeErrs = f.completeErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	return f.completeResult, nil
}

func (f *fakeTOTPLoginService) CancelTOTPLogin(challengeID string) { f.cancelled = challengeID }

func (f *fakeTOTPLoginService) ClearTOTPLoginChallenges() { f.cleared = true }

func TestLoginHandlerCompletesTOTPChallengeAfterRetry(t *testing.T) {
	now := time.Date(2026, time.July, 22, 13, 0, 0, 0, time.UTC)
	auth := &fakeTOTPLoginService{
		passwordResult: &dto.LoginResult{
			Status: dto.LoginStatusTOTPRequired, ChallengeID: "opaque", ChallengeExpiresAt: now.Add(5 * time.Minute),
		},
		completeResult: &dto.LoginResult{
			Status: dto.LoginStatusAuthenticated, RawSessionToken: "raw-session",
			User:             dto.User{Username: "alice", TOTPEnabled: true, RegisteredAt: now.Add(-time.Hour)},
			SessionExpiresAt: now.Add(30 * time.Minute),
		},
		completeErrs: []error{domain.ErrInvalidTOTP, nil},
	}
	state := &fakeSessionState{}
	terminal := &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password", "000000", "123456"}}

	if err := NewLoginHandler(auth, state, terminal).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state.token != "raw-session" || !slices.Equal(auth.codes, []string{"opaque:000000", "opaque:123456"}) {
		t.Fatalf("state/codes = %q/%v", state.token, auth.codes)
	}
	if !slices.Contains(terminal.messages, "Password accepted. Enter your authenticator code to finish login.") ||
		!slices.Contains(terminal.messages, "Invalid authenticator code. Try again or press Enter to cancel.") ||
		!slices.Contains(terminal.messages, "Login successful.") {
		t.Fatalf("messages = %v", terminal.messages)
	}
	if auth.cancelled != "" {
		t.Fatalf("successful challenge was cancelled: %q", auth.cancelled)
	}
}

func TestLoginHandlerCancelsBlankTOTPAndMapsExpiry(t *testing.T) {
	challenge := &dto.LoginResult{Status: dto.LoginStatusTOTPRequired, ChallengeID: "opaque"}
	auth := &fakeTOTPLoginService{passwordResult: challenge}
	terminal := &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password", ""}}
	if err := NewLoginHandler(auth, &fakeSessionState{}, terminal).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth.cancelled != "opaque" || !slices.Contains(terminal.messages, "Login cancelled.") {
		t.Fatalf("cancel/messages = %q/%v", auth.cancelled, terminal.messages)
	}

	auth = &fakeTOTPLoginService{passwordResult: challenge, completeErrs: []error{domain.ErrTOTPChallengeExpired}}
	terminal = &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password", "123456"}}
	if err := NewLoginHandler(auth, &fakeSessionState{}, terminal).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(terminal.messages, "Two-factor login challenge expired. Run `login` again.") {
		t.Fatalf("expiry messages = %v", terminal.messages)
	}
}

func TestLoginHandlerCancelsChallengeOnInterruptedCode(t *testing.T) {
	auth := &fakeTOTPLoginService{passwordResult: &dto.LoginResult{Status: dto.LoginStatusTOTPRequired, ChallengeID: "opaque"}}
	terminal := &loginInterruptTerminal{}
	err := NewLoginHandler(auth, &fakeSessionState{}, terminal).Handle(context.Background())
	if err == nil || auth.cancelled != "opaque" {
		t.Fatalf("interrupt error/cancel = %v/%q", err, auth.cancelled)
	}
}

type loginInterruptTerminal struct{ secretCalls int }

func (*loginInterruptTerminal) Prompt(string) (string, error) { return "alice", nil }
func (t *loginInterruptTerminal) PromptSecret(string) (string, error) {
	t.secretCalls++
	if t.secretCalls == 1 {
		return "password", nil
	}
	return "", errors.New("interrupted")
}
func (*loginInterruptTerminal) Println(string) {}
