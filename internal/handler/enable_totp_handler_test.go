package handler

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"

	"github.com/chzyer/readline"
)

type fakeEnrollmentService struct {
	setup        *dto.TOTPSetupResult
	beginErr     error
	confirmErrs  []error
	confirmCodes []string
	cancelToken  string
	cleared      bool
}

func (f *fakeEnrollmentService) BeginTOTPSetup(context.Context, string) (*dto.TOTPSetupResult, error) {
	return f.setup, f.beginErr
}

func (f *fakeEnrollmentService) ConfirmTOTPSetup(_ context.Context, _ string, code string) error {
	f.confirmCodes = append(f.confirmCodes, code)
	if len(f.confirmErrs) == 0 {
		return nil
	}
	err := f.confirmErrs[0]
	f.confirmErrs = f.confirmErrs[1:]
	return err
}

func (f *fakeEnrollmentService) CancelTOTPSetup(rawToken string) {
	f.cancelToken = rawToken
}

func (f *fakeEnrollmentService) ClearPendingTOTPSetups() {
	f.cleared = true
}

type fakeQRRenderer struct{ text string }

func (f *fakeQRRenderer) Render(text string) { f.text = text }

func TestEnableTOTPHandlerRetriesInvalidCodeThenSucceeds(t *testing.T) {
	setup := &dto.TOTPSetupResult{
		ProvisioningURI: "otpauth://totp/issuer:alice?secret=ABC",
		Issuer:          "issuer", AccountName: "alice", Period: 30, Digits: 6,
		ExpiresAt: time.Date(2026, time.July, 22, 7, 10, 0, 0, time.UTC),
	}
	enrollment := &fakeEnrollmentService{setup: setup, confirmErrs: []error{domain.ErrInvalidTOTP, nil}}
	state := &fakeSessionState{token: "raw-session"}
	terminal := &fakeTerminal{secrets: []string{"000000", "123456"}}
	qr := &fakeQRRenderer{}

	if err := NewEnableTOTPHandler(enrollment, state, terminal, qr).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if qr.text != setup.ProvisioningURI || !slices.Equal(enrollment.confirmCodes, []string{"000000", "123456"}) {
		t.Fatalf("QR/codes = %q/%v", qr.text, enrollment.confirmCodes)
	}
	if !slices.Contains(terminal.messages, "Provisioning URI: "+setup.ProvisioningURI) ||
		!slices.Contains(terminal.messages, "Invalid authenticator code. Try again or press Enter to cancel.") ||
		!slices.Contains(terminal.messages, "Two-factor authentication enabled successfully.") {
		t.Fatalf("messages = %v", terminal.messages)
	}
	if enrollment.cancelToken != "" {
		t.Fatalf("successful setup was cancelled with token %q", enrollment.cancelToken)
	}
}

func TestEnableTOTPHandlerCancelsBlankAndInterruptedInput(t *testing.T) {
	setup := &dto.TOTPSetupResult{ProvisioningURI: "otpauth://setup", Issuer: "issuer", AccountName: "alice", Period: 30, Digits: 6}

	enrollment := &fakeEnrollmentService{setup: setup}
	state := &fakeSessionState{token: "raw-session"}
	terminal := &fakeTerminal{secrets: []string{""}}
	if err := NewEnableTOTPHandler(enrollment, state, terminal, &fakeQRRenderer{}).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if enrollment.cancelToken != "raw-session" || len(enrollment.confirmCodes) != 0 {
		t.Fatalf("blank cancellation = %q/%v", enrollment.cancelToken, enrollment.confirmCodes)
	}

	enrollment = &fakeEnrollmentService{setup: setup}
	interrupt := &errorSecretTerminal{err: readline.ErrInterrupt}
	err := NewEnableTOTPHandler(enrollment, state, interrupt, &fakeQRRenderer{}).Handle(context.Background())
	if !errors.Is(err, readline.ErrInterrupt) || enrollment.cancelToken != "raw-session" {
		t.Fatalf("interrupt error/cancel = %v/%q", err, enrollment.cancelToken)
	}
}

func TestEnableTOTPHandlerClearsInvalidSession(t *testing.T) {
	enrollment := &fakeEnrollmentService{beginErr: domain.ErrSessionExpired}
	state := &fakeSessionState{token: "expired"}
	terminal := &fakeTerminal{}

	if err := NewEnableTOTPHandler(enrollment, state, terminal, &fakeQRRenderer{}).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state.token != "" || !slices.Equal(terminal.messages, []string{"Your session is no longer valid. Please log in again."}) {
		t.Fatalf("state/messages = %q/%v", state.token, terminal.messages)
	}
}

type errorSecretTerminal struct{ err error }

func (*errorSecretTerminal) Prompt(string) (string, error) { return "", errors.New("not used") }
func (t *errorSecretTerminal) PromptSecret(string) (string, error) {
	return "", t.err
}
func (*errorSecretTerminal) Println(string) {}
