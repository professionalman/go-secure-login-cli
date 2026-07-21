package handler

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalQRRendererProducesCompactQR(t *testing.T) {
	var output bytes.Buffer
	TerminalQRRenderer{Writer: &output}.Render("otpauth://totp/issuer:alice?secret=ABC")
	if output.Len() == 0 || !strings.Contains(output.String(), "\n") {
		t.Fatal("TerminalQRRenderer produced no multi-line QR output")
	}
}
