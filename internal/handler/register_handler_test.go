package handler

import (
	"context"
	"errors"
	"slices"
	"testing"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
)

type fakeRegistrationService struct {
	err   error
	input dto.RegisterInput
}

func (f *fakeRegistrationService) Register(_ context.Context, input dto.RegisterInput) (*dto.User, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	return &dto.User{Username: input.Username}, nil
}

type fakeTerminal struct {
	responses   []string
	secrets     []string
	messages    []string
	secretCalls int
}

func (f *fakeTerminal) Prompt(string) (string, error) {
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response, nil
}

func (f *fakeTerminal) PromptSecret(string) (string, error) {
	response := f.secrets[0]
	f.secrets = f.secrets[1:]
	f.secretCalls++
	return response, nil
}

func (f *fakeTerminal) Println(message string) {
	f.messages = append(f.messages, message)
}

func TestRegisterHandlerReadsSecretsAndReportsSuccess(t *testing.T) {
	auth := &fakeRegistrationService{}
	terminal := &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password", "password"}}
	handler := NewRegisterHandler(auth, terminal)

	if err := handler.Handle(context.Background()); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if terminal.secretCalls != 2 {
		t.Errorf("PromptSecret calls = %d, want 2", terminal.secretCalls)
	}
	if auth.input.Password != "password" || auth.input.PasswordConfirmation != "password" {
		t.Errorf("service input = %#v, want entered passwords", auth.input)
	}
	if !slices.Equal(terminal.messages, []string{"User registered successfully."}) {
		t.Errorf("messages = %v", terminal.messages)
	}
}

func TestRegisterHandlerMapsErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		message string
	}{
		{name: "duplicate", err: domain.ErrUserAlreadyExists, message: "Username already exists."},
		{name: "username", err: domain.ErrInvalidUsername, message: "Username is invalid. Use letters, numbers, dots, underscores, or hyphens."},
		{name: "password", err: domain.ErrInvalidPassword, message: "Password does not meet the configured length requirements."},
		{name: "mismatch", err: domain.ErrPasswordMismatch, message: "Passwords do not match."},
		{name: "internal", err: errors.New("database details must not leak"), message: "Registration failed. Please try again."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &fakeRegistrationService{err: tt.err}
			terminal := &fakeTerminal{responses: []string{"alice"}, secrets: []string{"password", "password"}}
			handler := NewRegisterHandler(auth, terminal)
			if err := handler.Handle(context.Background()); err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if !slices.Equal(terminal.messages, []string{tt.message}) {
				t.Errorf("messages = %v, want %q", terminal.messages, tt.message)
			}
		})
	}
}
