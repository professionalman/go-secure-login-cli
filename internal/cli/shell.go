package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
)

// Shell is the long-running interactive command loop.
type Shell struct {
	line  *readline.Instance
	state *State
	out   io.Writer
}

func NewShell(historyPath string, output io.Writer) (*Shell, error) {
	if err := prepareHistory(historyPath); err != nil {
		return nil, err
	}
	state := &State{}
	line, err := readline.NewEx(&readline.Config{
		Prompt:                 "auth-cli> ",
		HistoryFile:            historyPath,
		HistorySearchFold:      true,
		DisableAutoSaveHistory: true,
		AutoComplete:           NewCompleter(state),
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
		Stdout:                 output,
		Stderr:                 output,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize interactive shell: %w", err)
	}
	return &Shell{line: line, state: state, out: output}, nil
}

func (s *Shell) Close() error {
	return s.line.Close()
}

func (s *Shell) Run(ctx context.Context) error {
	fmt.Fprintln(s.out, "Authentication CLI ready. Run `help` to see available commands.")
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		raw, err := s.line.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read command: %w", err)
		}

		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 1 {
			fmt.Fprintln(s.out, "Commands do not accept arguments. Run `help` to see available commands.")
			continue
		}

		command := strings.ToLower(fields[0])
		if !knownCommand(s.state, command) {
			fmt.Fprintln(s.out, "Unknown command. Run `help` to see available commands.")
			continue
		}
		if err := s.line.SaveHistory(command); err != nil {
			fmt.Fprintln(s.out, "Warning: command history could not be saved.")
		}

		switch command {
		case "help":
			s.printHelp()
		case "exit":
			return nil
		case "register", "login":
			fmt.Fprintf(s.out, "%s is not available until its authentication milestone is implemented.\n", command)
		default:
			fmt.Fprintln(s.out, "This command is not available in the current milestone.")
		}
	}
}

func (s *Shell) printHelp() {
	fmt.Fprintln(s.out, "Available commands:")
	for _, command := range AvailableCommands(s.state) {
		description := commandDescription(command)
		fmt.Fprintf(s.out, "  %-12s %s\n", command, description)
	}
}

func commandDescription(command string) string {
	switch command {
	case "register":
		return "Create a user account (Milestone 2)."
	case "login":
		return "Authenticate with a username and password (Milestone 3)."
	case "whoami":
		return "Display the authenticated user."
	case "enable-2fa":
		return "Enable TOTP two-factor authentication."
	case "disable-2fa":
		return "Disable TOTP two-factor authentication."
	case "logout":
		return "Revoke the current session."
	case "help":
		return "Show commands available in the current state."
	case "exit":
		return "Close the application."
	default:
		return ""
	}
}
