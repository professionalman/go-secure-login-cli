package service

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestTOTPServiceGenerateAndValidateWithInjectedClock(t *testing.T) {
	now := time.Date(2026, time.July, 22, 1, 2, 3, 0, time.UTC)
	service := NewTOTPService(
		fakeClock{now: now},
		TOTPPolicy{Issuer: "InternshipAuthCLI", Period: 30, Skew: 1, Digits: 6},
		WithTOTPRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x42}, 20))),
	)
	provisioning, err := service.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	if provisioning.Secret == "" || provisioning.Issuer != "InternshipAuthCLI" || provisioning.AccountName != "alice" {
		t.Fatalf("provisioning data = %#v", provisioning)
	}
	parsed, err := url.Parse(provisioning.ProvisioningURI)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Query().Get("secret") != provisioning.Secret {
		t.Fatalf("provisioning URI = %q", provisioning.ProvisioningURI)
	}

	code, err := totp.GenerateCodeCustom(provisioning.Secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := service.Validate(provisioning.Secret, code)
	if err != nil || !valid {
		t.Fatalf("Validate(valid) = %v, %v", valid, err)
	}
	valid, err = service.Validate(provisioning.Secret, "000000")
	if err != nil {
		t.Fatal(err)
	}
	if valid && code != "000000" {
		t.Fatal("Validate() accepted an incorrect code")
	}
}

func TestTOTPServiceHonorsConfiguredSkewAndExpiry(t *testing.T) {
	period := uint(30)
	codeTime := time.Date(2026, time.July, 22, 2, 0, 0, 0, time.UTC)
	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCodeCustom(secret, codeTime, totp.ValidateOpts{
		Period: period, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}

	withinSkew := NewTOTPService(fakeClock{now: codeTime.Add(time.Duration(period) * time.Second)}, TOTPPolicy{
		Issuer: "issuer", Period: period, Skew: 1, Digits: 6,
	})
	valid, err := withinSkew.Validate(secret, code)
	if err != nil || !valid {
		t.Fatalf("Validate(within skew) = %v, %v", valid, err)
	}

	beyondSkew := NewTOTPService(fakeClock{now: codeTime.Add(2 * time.Duration(period) * time.Second)}, TOTPPolicy{
		Issuer: "issuer", Period: period, Skew: 1, Digits: 6,
	})
	valid, err = beyondSkew.Validate(secret, code)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("Validate() accepted a code outside configured skew")
	}
}

func TestTOTPServiceSupportsEightDigitsAndRejectsMalformedCodes(t *testing.T) {
	now := time.Date(2026, time.July, 22, 3, 0, 0, 0, time.UTC)
	secret := "JBSWY3DPEHPK3PXP"
	service := NewTOTPService(fakeClock{now: now}, TOTPPolicy{Issuer: "issuer", Period: 30, Skew: 0, Digits: 8})
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := service.Validate(secret, code)
	if err != nil || !valid {
		t.Fatalf("Validate(8 digits) = %v, %v", valid, err)
	}
	for _, malformed := range []string{"123456", "1234567x", "１２３４５６７８"} {
		valid, err := service.Validate(secret, malformed)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Fatalf("Validate() accepted malformed code %q", malformed)
		}
	}
}
