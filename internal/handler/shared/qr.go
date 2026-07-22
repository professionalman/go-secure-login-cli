package shared

import (
	"io"

	"github.com/mdp/qrterminal/v3"
)

type TerminalQRRenderer struct {
	Writer io.Writer
}

func (r TerminalQRRenderer) Render(content string) {
	qrterminal.GenerateHalfBlock(content, qrterminal.L, r.Writer)
}
