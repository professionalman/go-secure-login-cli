package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const sessionTokenBytes = 32

func GenerateSessionToken() (rawToken string, tokenHash string, err error) {
	random := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(random); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	rawToken = base64.RawURLEncoding.EncodeToString(random)
	return rawToken, HashSessionToken(rawToken), nil
}

func HashSessionToken(rawToken string) string {
	digest := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(digest[:])
}
