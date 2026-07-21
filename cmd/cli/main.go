package main

import (
	"context"
	"fmt"
	"os"

	appcli "auth-cli/internal/cli"
	"auth-cli/internal/clock"
	"auth-cli/internal/config"
	"auth-cli/internal/database"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"
	"auth-cli/internal/service"

	"github.com/google/uuid"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "Application startup failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	db, err := database.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	defer db.Close()

	if err := database.Migrate(ctx, db); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	unitOfWork := sqliterepository.NewUnitOfWork(db)
	serviceClock := clock.System{}
	sessionService := service.NewSessionService(
		users,
		sessions,
		unitOfWork,
		serviceClock,
		uuid.NewString,
		security.GenerateSessionToken,
		cfg.SessionTimeout,
	)
	totpCipher, err := security.NewAESGCMCipher(cfg.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("TOTP encryption initialization failed: %w", err)
	}
	totpService := service.NewTOTPService(serviceClock, service.TOTPPolicy{
		Issuer: cfg.TOTPIssuer,
		Period: uint(cfg.TOTPPeriod),
		Skew:   uint(cfg.TOTPSkew),
		Digits: cfg.TOTPDigits,
	})
	auth := service.NewAuthService(
		users,
		security.BcryptPasswordHasher{Cost: cfg.BcryptCost},
		serviceClock,
		uuid.NewString,
		service.RegistrationPolicy{
			MinimumUsernameLength: cfg.MinimumUsernameLength,
			MaximumUsernameLength: cfg.MaximumUsernameLength,
			MinimumPasswordLength: cfg.MinimumPasswordLength,
			MaximumPasswordLength: cfg.MaximumPasswordLength,
		},
		service.WithSessionService(sessionService),
		service.WithLoginSecurityPolicy(service.LoginSecurityPolicy{
			MaximumAttempts: cfg.MaximumLoginAttempts,
			LockoutDuration: cfg.AccountLockoutDuration,
		}),
		service.WithTOTPEnrollment(totpService, totpCipher, cfg.TOTPSetupTimeout),
		service.WithTOTPLogin(totpService, totpCipher, cfg.TOTPChallengeTimeout, security.GenerateSessionToken),
	)

	shell, err := appcli.NewShell(cfg.HistoryPath, os.Stdout, auth, auth, sessionService, auth, auth)
	if err != nil {
		return fmt.Errorf("CLI initialization failed: %w", err)
	}
	defer shell.Close()

	if err := shell.Run(ctx); err != nil {
		return fmt.Errorf("CLI stopped unexpectedly: %w", err)
	}
	return nil
}
