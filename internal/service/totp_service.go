package service

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"auth-cli/internal/clock"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type TOTPProvisioningData struct {
	Secret          string
	ProvisioningURI string
	Issuer          string
	AccountName     string
	Period          uint
	Digits          int
}

type TOTPService interface {
	Generate(accountName string) (*TOTPProvisioningData, error)
	Validate(secret, code string) (bool, error)
}

type TOTPPolicy struct {
	Issuer string
	Period uint
	Skew   uint
	Digits int
}

type TOTPOption func(*DefaultTOTPService)

func WithTOTPRandomReader(random io.Reader) TOTPOption {
	return func(service *DefaultTOTPService) {
		service.random = random
	}
}

type DefaultTOTPService struct {
	clock  clock.Clock
	policy TOTPPolicy
	random io.Reader
}

func NewTOTPService(serviceClock clock.Clock, policy TOTPPolicy, options ...TOTPOption) *DefaultTOTPService {
	service := &DefaultTOTPService{clock: serviceClock, policy: policy}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *DefaultTOTPService) Generate(accountName string) (*TOTPProvisioningData, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.policy.Issuer,
		AccountName: accountName,
		Period:      s.policy.Period,
		Digits:      otp.Digits(s.policy.Digits),
		Algorithm:   otp.AlgorithmSHA1,
		Rand:        s.random,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP provisioning data: %w", err)
	}
	return &TOTPProvisioningData{
		Secret: key.Secret(), ProvisioningURI: key.URL(),
		Issuer: s.policy.Issuer, AccountName: accountName,
		Period: s.policy.Period, Digits: s.policy.Digits,
	}, nil
}

func (s *DefaultTOTPService) Validate(secret, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if len(code) != s.policy.Digits {
		return false, nil
	}
	for _, character := range code {
		if character > unicode.MaxASCII || !unicode.IsDigit(character) {
			return false, nil
		}
	}
	valid, err := totp.ValidateCustom(code, secret, s.clock.Now().UTC(), totp.ValidateOpts{
		Period: s.policy.Period, Skew: s.policy.Skew,
		Digits: otp.Digits(s.policy.Digits), Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false, fmt.Errorf("validate TOTP code: %w", err)
	}
	return valid, nil
}
