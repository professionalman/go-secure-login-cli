package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
)

func (f *fakeUserRepository) EnableTOTP(_ context.Context, userID, encryptedSecret string, updatedAt time.Time) error {
	for _, user := range f.users {
		if user.ID != userID {
			continue
		}
		if user.TOTPEnabled {
			return repository.ErrConflict
		}
		user.TOTPEnabled = true
		secret := encryptedSecret
		user.TOTPSecretEncrypted = &secret
		user.UpdatedAt = updatedAt
		return nil
	}
	return repository.ErrNotFound
}

type fakeEnrollmentSessions struct {
	user dto.AuthenticatedUser
	err  error
}

func (*fakeEnrollmentSessions) FinalizeLogin(context.Context, string) (*dto.SessionResult, error) {
	return nil, errors.New("not used")
}

func (f *fakeEnrollmentSessions) ValidateSession(context.Context, string) (*dto.AuthenticatedUser, error) {
	if f.err != nil {
		return nil, f.err
	}
	result := f.user
	return &result, nil
}

func (*fakeEnrollmentSessions) Logout(context.Context, string) error {
	return errors.New("not used")
}

type fakeTOTPService struct {
	generated []*TOTPProvisioningData
	validCode string
	validated []string
}

func (f *fakeTOTPService) Generate(string) (*TOTPProvisioningData, error) {
	result := f.generated[0]
	f.generated = f.generated[1:]
	return result, nil
}

func (f *fakeTOTPService) Validate(secret, code string) (bool, error) {
	f.validated = append(f.validated, secret)
	return code == f.validCode, nil
}

type fakeSecretCipher struct {
	plaintext string
	err       error
}

func (f *fakeSecretCipher) Encrypt(plaintext string) (string, error) {
	f.plaintext = plaintext
	if f.err != nil {
		return "", f.err
	}
	return "encrypted:" + plaintext, nil
}

func (*fakeSecretCipher) Decrypt(string) (string, error) {
	return "", errors.New("not used")
}

func TestTOTPEnrollmentReplacementConfirmationAndCancellationIsolation(t *testing.T) {
	now := time.Date(2026, time.July, 22, 5, 0, 0, 0, time.UTC)
	user := &domain.User{ID: "u", Username: "alice", RegisteredAt: now.Add(-time.Hour)}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	sessions := &fakeEnrollmentSessions{user: dto.AuthenticatedUser{User: dto.User{ID: "u", Username: "alice"}}}
	totpService := &fakeTOTPService{
		generated: []*TOTPProvisioningData{
			{Secret: "first-secret", ProvisioningURI: "otpauth://first", Issuer: "issuer", AccountName: "alice", Period: 30, Digits: 6},
			{Secret: "second-secret", ProvisioningURI: "otpauth://second", Issuer: "issuer", AccountName: "alice", Period: 30, Digits: 6},
		},
		validCode: "123456",
	}
	cipher := &fakeSecretCipher{}
	auth := newEnrollmentTestAuth(repo, sessions, totpService, cipher, fakeClock{now: now})

	first, err := auth.BeginTOTPSetup(context.Background(), "session-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := auth.BeginTOTPSetup(context.Background(), "session-two")
	if err != nil {
		t.Fatal(err)
	}
	if first.ProvisioningURI == second.ProvisioningURI || second.ExpiresAt != now.Add(10*time.Minute) {
		t.Fatalf("replacement results = %#v / %#v", first, second)
	}
	if pendingSetupCount(auth) != 1 {
		t.Fatalf("pending setup count = %d, want 1", pendingSetupCount(auth))
	}

	auth.CancelTOTPSetup("session-one")
	if pendingSetupCount(auth) != 1 {
		t.Fatal("cancelling the replaced session removed the current setup")
	}
	if err := auth.ConfirmTOTPSetup(context.Background(), "session-two", "000000"); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("invalid ConfirmTOTPSetup() error = %v", err)
	}
	if pendingSetupCount(auth) != 1 {
		t.Fatal("invalid code removed pending setup")
	}
	if err := auth.ConfirmTOTPSetup(context.Background(), "session-two", "123456"); err != nil {
		t.Fatal(err)
	}
	if !user.TOTPEnabled || user.TOTPSecretEncrypted == nil || *user.TOTPSecretEncrypted != "encrypted:second-secret" {
		t.Fatalf("persisted TOTP state = %#v", user)
	}
	if cipher.plaintext != "second-secret" || pendingSetupCount(auth) != 0 {
		t.Fatalf("cipher/pending = %q/%d", cipher.plaintext, pendingSetupCount(auth))
	}
}

func TestTOTPEnrollmentExpiresAtBoundaryAndClearsOnShutdown(t *testing.T) {
	now := time.Date(2026, time.July, 22, 6, 0, 0, 0, time.UTC)
	serviceClock := &mutableClock{now: now}
	user := &domain.User{ID: "u", Username: "alice", RegisteredAt: now.Add(-time.Hour)}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	sessions := &fakeEnrollmentSessions{user: dto.AuthenticatedUser{User: dto.User{ID: "u", Username: "alice"}}}
	totpService := &fakeTOTPService{
		generated: []*TOTPProvisioningData{
			{Secret: "secret", ProvisioningURI: "otpauth://setup", Issuer: "issuer", AccountName: "alice", Period: 30, Digits: 6},
			{Secret: "replacement", ProvisioningURI: "otpauth://replacement", Issuer: "issuer", AccountName: "alice", Period: 30, Digits: 6},
		},
		validCode: "123456",
	}
	auth := newEnrollmentTestAuth(repo, sessions, totpService, &fakeSecretCipher{}, serviceClock)

	setup, err := auth.BeginTOTPSetup(context.Background(), "session")
	if err != nil {
		t.Fatal(err)
	}
	serviceClock.now = setup.ExpiresAt
	if err := auth.ConfirmTOTPSetup(context.Background(), "session", "123456"); !errors.Is(err, domain.ErrTOTPSetupExpired) {
		t.Fatalf("ConfirmTOTPSetup() at expiry error = %v", err)
	}
	if pendingSetupCount(auth) != 0 || user.TOTPEnabled {
		t.Fatalf("expired setup state = %d/%v", pendingSetupCount(auth), user.TOTPEnabled)
	}

	if _, err := auth.BeginTOTPSetup(context.Background(), "session"); err != nil {
		t.Fatal(err)
	}
	auth.ClearPendingTOTPSetups()
	if pendingSetupCount(auth) != 0 {
		t.Fatal("ClearPendingTOTPSetups() retained process-local setup")
	}
	if err := auth.ConfirmTOTPSetup(context.Background(), "session", "123456"); !errors.Is(err, domain.ErrTOTPSetupNotFound) {
		t.Fatalf("ConfirmTOTPSetup() after clear error = %v", err)
	}
}

func TestTOTPEnrollmentRejectsEnabledAndInvalidSessions(t *testing.T) {
	now := time.Now().UTC()
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": {ID: "u", Username: "alice"}}}
	totpService := &fakeTOTPService{}
	sessions := &fakeEnrollmentSessions{user: dto.AuthenticatedUser{User: dto.User{ID: "u", Username: "alice", TOTPEnabled: true}}}
	auth := newEnrollmentTestAuth(repo, sessions, totpService, &fakeSecretCipher{}, fakeClock{now: now})

	if _, err := auth.BeginTOTPSetup(context.Background(), "session"); !errors.Is(err, domain.ErrTOTPAlreadyEnabled) {
		t.Fatalf("BeginTOTPSetup(enabled) error = %v", err)
	}
	sessions.err = domain.ErrSessionExpired
	if _, err := auth.BeginTOTPSetup(context.Background(), "session"); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("BeginTOTPSetup(expired session) error = %v", err)
	}
}

func newEnrollmentTestAuth(
	users repository.UserRepository,
	sessions SessionService,
	totpService TOTPService,
	cipher SecretCipher,
	serviceClock interface{ Now() time.Time },
) *DefaultAuthService {
	return NewAuthService(
		users,
		fakeHasher{},
		serviceClock,
		func() string { return "unused" },
		RegistrationPolicy{},
		WithSessionService(sessions),
		WithTOTPEnrollment(totpService, cipher, 10*time.Minute),
	)
}

func pendingSetupCount(service *DefaultAuthService) int {
	store := service.totpEnrollment.store
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.byUser)
}
