package totp

//go:generate go tool mockgen -source=interface.go -destination=mocks/mock_totp.go -package=mocks

import (
	"context"

	"auth-cli/internal/dto"
)

type ITOTPService interface {
	BeginSetup(ctx context.Context, rawSessionToken string) (*dto.TOTPSetupResult, error)
	ConfirmSetup(ctx context.Context, rawSessionToken, code string) error
	CancelSetup(rawSessionToken string)
	ClearPendingSetups()
	ValidateEncryptedCode(encryptedSecret, code string) (bool, error)
	Disable(ctx context.Context, rawSessionToken, password, code string) error
}

type ISecretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}
