package security

import (
	"encoding/base64"
	"testing"
)

func TestGenerateSessionToken(t *testing.T) {
	raw, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken() error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("raw token is not unpadded Base64URL: %v", err)
	}
	if len(decoded) != sessionTokenBytes {
		t.Errorf("decoded token length = %d, want %d", len(decoded), sessionTokenBytes)
	}
	if hash == raw {
		t.Fatal("stored hash equals raw token")
	}
	if hash != HashSessionToken(raw) {
		t.Fatal("returned token hash is inconsistent")
	}
}

func TestGenerateSessionTokenIsUnique(t *testing.T) {
	first, _, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two generated session tokens are equal")
	}
}
