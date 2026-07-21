package cli

import (
	"fmt"
	"io"

	"github.com/chzyer/readline"
)

const shellPrompt = "auth-cli> "

type terminal struct {
	line *readline.Instance
	out  io.Writer
}

func (t terminal) Prompt(label string) (string, error) {
	t.line.SetPrompt(label)
	defer t.line.SetPrompt(shellPrompt)
	return t.line.Readline()
}

func (t terminal) PromptSecret(label string) (string, error) {
	value, err := t.line.ReadPassword(label)
	return string(value), err
}

func (t terminal) Println(message string) {
	fmt.Fprintln(t.out, message)
}
