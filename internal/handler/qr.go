package handler

import (
	"io"

	"github.com/mdp/qrterminal/v3"
)

type QRRenderer interface {
	Render(text string)
}

type TerminalQRRenderer struct {
	Writer io.Writer
}

func (r TerminalQRRenderer) Render(text string) {
	qrterminal.GenerateHalfBlock(text, qrterminal.L, r.Writer)
}
