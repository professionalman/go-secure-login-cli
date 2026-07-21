package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var environmentKeys = []string{
	"APP_ENV",
	"DATABASE_PATH",
	"HISTORY_PATH",
	"MIN_USERNAME_LENGTH",
	"MAX_USERNAME_LENGTH",
	"MIN_PASSWORD_LENGTH",
	"MAX_PASSWORD_LENGTH",
	"BCRYPT_COST",
	"MAX_LOGIN_ATTEMPTS",
	"ACCOUNT_LOCKOUT_DURATION",
	"SESSION_TIMEOUT",
	"TOTP_ISSUER",
	"TOTP_PERIOD",
	"TOTP_SKEW",
	"TOTP_DIGITS",
	"TOTP_SETUP_TIMEOUT",
	"TOTP_CHALLENGE_TIMEOUT",
	"TOTP_ENCRYPTION_KEY_BASE64",
}

func TestLoadUsesDefaults(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("TOTP_ENCRYPTION_KEY_BASE64", validEncryptionKey())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.AppEnvironment != defaultAppEnvironment {
		t.Errorf("AppEnvironment = %q, want %q", cfg.AppEnvironment, defaultAppEnvironment)
	}
	if cfg.DatabasePath != defaultDatabasePath {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, defaultDatabasePath)
	}
	if cfg.HistoryPath != defaultHistoryPath {
		t.Errorf("HistoryPath = %q, want %q", cfg.HistoryPath, defaultHistoryPath)
	}
	if cfg.AccountLockoutDuration != 15*time.Minute {
		t.Errorf("AccountLockoutDuration = %v, want 15m", cfg.AccountLockoutDuration)
	}
	if len(cfg.TOTPEncryptionKey) != 32 {
		t.Errorf("encryption key length = %d, want 32", len(cfg.TOTPEncryptionKey))
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		variable  string
		value     string
		wantError string
	}{
		{name: "integer", variable: "MAX_LOGIN_ATTEMPTS", value: "many", wantError: "must be an integer"},
		{name: "positive integer", variable: "TOTP_PERIOD", value: "0", wantError: "must be a positive integer"},
		{name: "nonnegative skew", variable: "TOTP_SKEW", value: "-1", wantError: "must not be negative"},
		{name: "duration", variable: "SESSION_TIMEOUT", value: "tomorrow", wantError: "must be a positive duration"},
		{name: "bcrypt range", variable: "BCRYPT_COST", value: "3", wantError: "must be between"},
		{name: "password maximum", variable: "MAX_PASSWORD_LENGTH", value: "73", wantError: "must not exceed 72"},
		{name: "TOTP digits", variable: "TOTP_DIGITS", value: "7", wantError: "must be either 6 or 8"},
		{name: "username range", variable: "MIN_USERNAME_LENGTH", value: "51", wantError: "must not exceed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvironment(t)
			t.Setenv("TOTP_ENCRYPTION_KEY_BASE64", validEncryptionKey())
			t.Setenv(tt.variable, tt.value)

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.wantError)
			}
		})
	}
}

func TestLoadRejectsInvalidEncryptionKeys(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "missing", value: "", wantError: "is required"},
		{name: "malformed", value: "not-base64!", wantError: "valid Base64"},
		{name: "wrong size", value: base64.StdEncoding.EncodeToString([]byte("too short")), wantError: "exactly 32 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvironment(t)
			t.Setenv("TOTP_ENCRYPTION_KEY_BASE64", tt.value)

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.wantError)
			}
		})
	}
}

func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range environmentKeys {
		t.Setenv(key, "")
	}
}

func validEncryptionKey() string {
	return base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
}
