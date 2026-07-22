package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	appcli "auth-cli/internal/cli"
	"auth-cli/internal/config"
	database "auth-cli/internal/database/postgres"
	"auth-cli/internal/repository/loginsecurity"
	sessionrepository "auth-cli/internal/repository/session"
	"auth-cli/internal/repository/transaction"
	userrepository "auth-cli/internal/repository/user"
	"auth-cli/internal/security"
	authservice "auth-cli/internal/service/auth"
	sessionservice "auth-cli/internal/service/session"
	totpservice "auth-cli/internal/service/totp"

	"github.com/google/uuid"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Application startup failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if err := config.LoadEnvFile(".env.local"); err != nil {
		return fmt.Errorf("load local environment: %w", err)
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	defer db.Close()
	if err := database.Migrate(ctx, db); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}
	redisClient, err := loginsecurity.Open(ctx, cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("login security initialization failed: %w", err)
	}
	defer redisClient.Close()

	users := userrepository.NewPostgresRepository(db)
	sessions := sessionrepository.NewPostgresRepository(db)
	unitOfWork := transaction.NewPostgresUnitOfWork(db)
	loginSecurity := loginsecurity.NewRedisRepository(redisClient)
	if err := sessions.DeleteExpired(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("expired session cleanup failed: %w", err)
	}
	passwords := security.BcryptPasswordManager{Cost: cfg.BcryptCost}
	sessionService := sessionservice.NewService(
		users, sessions, unitOfWork, uuid.NewString,
		security.GenerateSessionToken, cfg.SessionTimeout,
	)
	cipher, err := security.NewAESGCMCipher(cfg.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("TOTP encryption initialization failed: %w", err)
	}
	totpService := totpservice.NewService(
		users, sessionService, passwords, cipher,
		totpservice.Policy{
			Issuer: cfg.TOTPIssuer, Period: uint(cfg.TOTPPeriod),
			Skew: uint(cfg.TOTPSkew), Digits: cfg.TOTPDigits,
		},
		cfg.TOTPSetupTimeout,
	)
	registrationPolicy := authservice.RegistrationPolicy{
		MinimumUsernameLength: cfg.MinimumUsernameLength,
		MaximumUsernameLength: cfg.MaximumUsernameLength,
		MinimumPasswordLength: cfg.MinimumPasswordLength,
		MaximumPasswordLength: cfg.MaximumPasswordLength,
	}
	authService := authservice.NewService(
		users, passwords, sessionService, totpService, loginSecurity,
		uuid.NewString, security.GenerateSessionToken,
		registrationPolicy,
		authservice.LoginSecurityPolicy{
			MaximumAttempts: cfg.MaximumLoginAttempts,
			LockoutDuration: cfg.AccountLockoutDuration,
		},
		cfg.TOTPChallengeTimeout,
	)
	shell, err := appcli.NewShell(
		cfg.HistoryPath, os.Stdout, authService, sessionService, totpService,
		registrationPolicy,
	)
	if err != nil {
		return fmt.Errorf("CLI initialization failed: %w", err)
	}
	defer shell.Close()
	if err := shell.Run(ctx); err != nil {
		return fmt.Errorf("CLI stopped unexpectedly: %w", err)
	}
	return nil
}
