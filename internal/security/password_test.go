package security

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	const password = "correct horse battery staple"
	hash, err := HashPassword(password, 4)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == password {
		t.Fatal("HashPassword() returned plaintext")
	}
	if err := VerifyPassword(hash, password); err != nil {
		t.Fatalf("VerifyPassword(correct) error = %v", err)
	}
	if err := VerifyPassword(hash, "wrong password"); err == nil {
		t.Fatal("VerifyPassword(wrong) succeeded")
	}
}

func TestHashPasswordRejectsMoreThan72Bytes(t *testing.T) {
	password := make([]byte, 73)
	for index := range password {
		password[index] = 'a'
	}
	if _, err := HashPassword(string(password), 4); err == nil {
		t.Fatal("HashPassword() accepted a password longer than 72 bytes")
	}
}
