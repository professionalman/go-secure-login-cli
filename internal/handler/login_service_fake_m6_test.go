package handler

import (
	"context"

	"auth-cli/internal/dto"
)

func (f *fakeLoginService) CompleteTOTPLogin(context.Context, string, string) (*dto.LoginResult, error) {
	return nil, f.err
}

func (*fakeLoginService) CancelTOTPLogin(string) {}

func (*fakeLoginService) ClearTOTPLoginChallenges() {}
