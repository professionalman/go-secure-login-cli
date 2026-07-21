package dto

import "time"

type TOTPSetupResult struct {
	ProvisioningURI string
	Issuer          string
	AccountName     string
	Period          uint
	Digits          int
	ExpiresAt       time.Time
}
