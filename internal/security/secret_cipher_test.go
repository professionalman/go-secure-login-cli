package security

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAESGCMCipherRoundTripAndRandomNonces(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewAESGCMCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	first, err := cipher.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("encrypting the same secret reused a nonce")
	}
	decrypted, err := cipher.Decrypt(first)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Decrypt() = %q", decrypted)
	}
}

func TestAESGCMCipherRejectsTamperingAndWrongKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewAESGCMCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] ^= 0xff
	if _, err := cipher.Decrypt(base64.StdEncoding.EncodeToString(payload)); err == nil {
		t.Fatal("Decrypt() accepted tampered ciphertext")
	}

	wrongKey := []byte(strings.Repeat("x", AES256KeyBytes))
	wrongCipher, err := NewAESGCMCipher(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongCipher.Decrypt(encrypted); err == nil {
		t.Fatal("Decrypt() accepted a different encryption key")
	}
}

func TestAESGCMCipherValidatesKeyAndPayload(t *testing.T) {
	if _, err := NewAESGCMCipher([]byte("short")); err == nil {
		t.Fatal("NewAESGCMCipher() accepted a non-256-bit key")
	}
	cipher, err := NewAESGCMCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Decrypt("not-base64"); err == nil {
		t.Fatal("Decrypt() accepted invalid Base64")
	}
}
