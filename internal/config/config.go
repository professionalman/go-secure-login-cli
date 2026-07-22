package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAppEnvironment          = "development"
	defaultDatabaseURL             = "postgres://auth_cli:auth_cli@localhost:5432/auth_cli?sslmode=disable"
	defaultRedisURL                = "redis://localhost:6379/0"
	defaultHistoryPath             = "data/.auth-cli-history"
	defaultMinimumUsernameLength   = 3
	defaultMaximumUsernameLength   = 50
	defaultMinimumPasswordLength   = 8
	defaultMaximumPasswordLength   = 72
	defaultBcryptCost              = 12
	defaultMaximumLoginAttempts    = 5
	defaultAccountLockoutDuration  = 15 * time.Minute
	defaultSessionTimeout          = 30 * time.Minute
	defaultTOTPIssuer              = "InternshipAuthCLI"
	defaultTOTPPeriod              = 30
	defaultTOTPSkew                = 1
	defaultTOTPDigits              = 6
	defaultTOTPSetupTimeout        = 10 * time.Minute
	defaultTOTPChallengeTimeout    = 5 * time.Minute
	minimumBcryptCost              = 4
	maximumBcryptCost              = 31
	requiredTOTPEncryptionKeyBytes = 32
)

// Config is the validated runtime configuration for the application.
type Config struct {
	AppEnvironment         string
	DatabaseURL            string
	RedisURL               string
	HistoryPath            string
	MinimumUsernameLength  int
	MaximumUsernameLength  int
	MinimumPasswordLength  int
	MaximumPasswordLength  int
	BcryptCost             int
	MaximumLoginAttempts   int
	AccountLockoutDuration time.Duration
	SessionTimeout         time.Duration
	TOTPIssuer             string
	TOTPPeriod             int
	TOTPSkew               int
	TOTPDigits             int
	TOTPSetupTimeout       time.Duration
	TOTPChallengeTimeout   time.Duration
	TOTPEncryptionKey      []byte
}

// Load reads configuration from environment variables and validates every
// value before returning it.
func Load() (Config, error) {
	var cfg Config
	var err error

	cfg.AppEnvironment = valueOrDefault("APP_ENV", defaultAppEnvironment)
	cfg.DatabaseURL = valueOrDefault("DATABASE_URL", defaultDatabaseURL)
	cfg.RedisURL = valueOrDefault("REDIS_URL", defaultRedisURL)
	cfg.HistoryPath = valueOrDefault("HISTORY_PATH", defaultHistoryPath)
	cfg.TOTPIssuer = valueOrDefault("TOTP_ISSUER", defaultTOTPIssuer)

	if cfg.MinimumUsernameLength, err = positiveInt("MIN_USERNAME_LENGTH", defaultMinimumUsernameLength); err != nil {
		return Config{}, err
	}
	if cfg.MaximumUsernameLength, err = positiveInt("MAX_USERNAME_LENGTH", defaultMaximumUsernameLength); err != nil {
		return Config{}, err
	}
	if cfg.MinimumPasswordLength, err = positiveInt("MIN_PASSWORD_LENGTH", defaultMinimumPasswordLength); err != nil {
		return Config{}, err
	}
	if cfg.MaximumPasswordLength, err = positiveInt("MAX_PASSWORD_LENGTH", defaultMaximumPasswordLength); err != nil {
		return Config{}, err
	}
	if cfg.BcryptCost, err = positiveInt("BCRYPT_COST", defaultBcryptCost); err != nil {
		return Config{}, err
	}
	if cfg.MaximumLoginAttempts, err = positiveInt("MAX_LOGIN_ATTEMPTS", defaultMaximumLoginAttempts); err != nil {
		return Config{}, err
	}
	if cfg.TOTPPeriod, err = positiveInt("TOTP_PERIOD", defaultTOTPPeriod); err != nil {
		return Config{}, err
	}
	if cfg.TOTPSkew, err = nonNegativeInt("TOTP_SKEW", defaultTOTPSkew); err != nil {
		return Config{}, err
	}
	if cfg.TOTPDigits, err = positiveInt("TOTP_DIGITS", defaultTOTPDigits); err != nil {
		return Config{}, err
	}

	if cfg.AccountLockoutDuration, err = positiveDuration("ACCOUNT_LOCKOUT_DURATION", defaultAccountLockoutDuration); err != nil {
		return Config{}, err
	}
	if cfg.SessionTimeout, err = positiveDuration("SESSION_TIMEOUT", defaultSessionTimeout); err != nil {
		return Config{}, err
	}
	if cfg.TOTPSetupTimeout, err = positiveDuration("TOTP_SETUP_TIMEOUT", defaultTOTPSetupTimeout); err != nil {
		return Config{}, err
	}
	if cfg.TOTPChallengeTimeout, err = positiveDuration("TOTP_CHALLENGE_TIMEOUT", defaultTOTPChallengeTimeout); err != nil {
		return Config{}, err
	}

	if err := validateRanges(cfg); err != nil {
		return Config{}, err
	}

	cfg.TOTPEncryptionKey, err = encryptionKey()
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validateRanges(cfg Config) error {
	if strings.TrimSpace(cfg.AppEnvironment) == "" {
		return errors.New("APP_ENV must not be empty")
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return errors.New("DATABASE_URL must not be empty")
	}
	if strings.TrimSpace(cfg.RedisURL) == "" {
		return errors.New("REDIS_URL must not be empty")
	}
	if strings.TrimSpace(cfg.HistoryPath) == "" {
		return errors.New("HISTORY_PATH must not be empty")
	}
	if strings.TrimSpace(cfg.TOTPIssuer) == "" {
		return errors.New("TOTP_ISSUER must not be empty")
	}
	if cfg.MinimumUsernameLength > cfg.MaximumUsernameLength {
		return errors.New("MIN_USERNAME_LENGTH must not exceed MAX_USERNAME_LENGTH")
	}
	if cfg.MinimumPasswordLength > cfg.MaximumPasswordLength {
		return errors.New("MIN_PASSWORD_LENGTH must not exceed MAX_PASSWORD_LENGTH")
	}
	if cfg.MaximumPasswordLength > defaultMaximumPasswordLength {
		return fmt.Errorf("MAX_PASSWORD_LENGTH must not exceed %d bytes", defaultMaximumPasswordLength)
	}
	if cfg.BcryptCost < minimumBcryptCost || cfg.BcryptCost > maximumBcryptCost {
		return fmt.Errorf("BCRYPT_COST must be between %d and %d", minimumBcryptCost, maximumBcryptCost)
	}
	if cfg.TOTPDigits != 6 && cfg.TOTPDigits != 8 {
		return errors.New("TOTP_DIGITS must be either 6 or 8")
	}
	return nil
}

func valueOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func positiveInt(name string, fallback int) (int, error) {
	value, err := integer(name, fallback)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func nonNegativeInt(name string, fallback int) (int, error) {
	value, err := integer(name, fallback)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}
	return value, nil
}

func integer(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return value, nil
}

func positiveDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return value, nil
}

func encryptionKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("TOTP_ENCRYPTION_KEY_BASE64"))
	if raw == "" {
		return nil, errors.New("TOTP_ENCRYPTION_KEY_BASE64 is required")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("TOTP_ENCRYPTION_KEY_BASE64 must be valid Base64")
	}
	if len(key) != requiredTOTPEncryptionKeyBytes {
		return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY_BASE64 must decode to exactly %d bytes", requiredTOTPEncryptionKeyBytes)
	}
	return key, nil
}
