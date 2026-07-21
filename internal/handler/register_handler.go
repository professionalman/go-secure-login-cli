package handler

import (
	"context"
	"errors"
	"fmt"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/service"
)

type Terminal interface {
	Prompt(label string) (string, error)
	PromptSecret(label string) (string, error)
	Println(message string)
}

type RegisterHandler struct {
	auth     service.AuthService
	terminal Terminal
}

func NewRegisterHandler(auth service.AuthService, terminal Terminal) *RegisterHandler {
	return &RegisterHandler{auth: auth, terminal: terminal}
}

func (h *RegisterHandler) Handle(ctx context.Context) error {
	username, err := h.terminal.Prompt("Username: ")
	if err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	password, err := h.terminal.PromptSecret("Password: ")
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	confirmation, err := h.terminal.PromptSecret("Confirm password: ")
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}

	_, err = h.auth.Register(ctx, dto.RegisterInput{
		Username:             username,
		Password:             password,
		PasswordConfirmation: confirmation,
	})
	switch {
	case err == nil:
		h.terminal.Println("User registered successfully.")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		h.terminal.Println("Username already exists.")
	case errors.Is(err, domain.ErrInvalidUsername):
		h.terminal.Println("Username is invalid. Use letters, numbers, dots, underscores, or hyphens.")
	case errors.Is(err, domain.ErrInvalidPassword):
		h.terminal.Println("Password does not meet the configured length requirements.")
	case errors.Is(err, domain.ErrPasswordMismatch):
		h.terminal.Println("Passwords do not match.")
	default:
		h.terminal.Println("Registration failed. Please try again.")
	}
	return nil
}
