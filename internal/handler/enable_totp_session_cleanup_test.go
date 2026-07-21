package handler

import (
	"context"
	"testing"

	"auth-cli/internal/domain"
)

func TestEnableTOTPHandlerCancelsPendingStateWhenSessionIsInvalid(t *testing.T) {
	enrollment := &fakeEnrollmentService{beginErr: domain.ErrSessionRevoked}
	state := &fakeSessionState{token: "revoked-session"}

	if err := NewEnableTOTPHandler(enrollment, state, &fakeTerminal{}, &fakeQRRenderer{}).Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if enrollment.cancelToken != "revoked-session" || state.token != "" {
		t.Fatalf("cancel/state = %q/%q", enrollment.cancelToken, state.token)
	}
}
