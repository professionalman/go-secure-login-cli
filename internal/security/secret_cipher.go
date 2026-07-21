package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const AES256KeyBytes = 32

type AESGCMCipher struct {
	aead   cipher.AEAD
	random io.Reader
}

func NewAESGCMCipher(key []byte) (*AESGCMCipher, error) {
	return newAESGCMCipher(key, rand.Reader)
}

func newAESGCMCipher(key []byte, random io.Reader) (*AESGCMCipher, error) {
	if len(key) != AES256KeyBytes {
		return nil, fmt.Errorf("AES-GCM key must be exactly %d bytes", AES256KeyBytes)
	}
	if random == nil {
		return nil, errors.New("AES-GCM random source is required")
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, fmt.Errorf("initialize AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-GCM: %w", err)
	}
	return &AESGCMCipher{aead: aead, random: random}, nil
}

func (c *AESGCMCipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return "", fmt.Errorf("generate encryption nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, sealed...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

func (c *AESGCMCipher) Decrypt(encoded string) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("encrypted secret is not valid Base64")
	}
	nonceSize := c.aead.NonceSize()
	if len(payload) < nonceSize+c.aead.Overhead() {
		return "", errors.New("encrypted secret is malformed")
	}
	plaintext, err := c.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil {
		return "", errors.New("encrypted secret authentication failed")
	}
	return string(plaintext), nil
}
