package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"auth-cli/internal/handler"
	"auth-cli/internal/service"

	"github.com/chzyer/readline"
)

// Shell is the long-running interactive command loop.
type Shell struct {
	line         *readline.Instance
	state        *State
	out          io.Writer
	register     *handler.RegisterHandler
	login        *handler.LoginHandler
	whoami       *handler.WhoAmIHandler
	logout       *handler.LogoutHandler
	enableTOTP   *handler.EnableTOTPHandler
	disableTOTP  *handler.DisableTOTPHandler
	loginService service.LoginService
	enrollment   service.TOTPEnrollmentService
}

func NewShell(
	historyPath string,
	output io.Writer,
	auth service.AuthService,
	login service.LoginService,
	sessions service.SessionService,
	enrollment service.TOTPEnrollmentService,
	disable service.TOTPDisableService,
) (*Shell, error) {
	if err := prepareHistory(historyPath); err != nil {
		return nil, err
	}
	state := &State{}
	line, err := readline.NewEx(&readline.Config{
		Prompt:                 shellPrompt,
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
	terminal := terminal{line: line, out: output}
	return &Shell{
		line: line, state: state, out: output, loginService: login, enrollment: enrollment,
		register:    handler.NewRegisterHandler(auth, terminal),
		login:       handler.NewLoginHandler(login, state, terminal),
		whoami:      handler.NewWhoAmIHandler(sessions, state, terminal),
		logout:      handler.NewLogoutHandler(sessions, state, terminal),
		enableTOTP:  handler.NewEnableTOTPHandler(enrollment, state, terminal, handler.TerminalQRRenderer{Writer: output}),
		disableTOTP: handler.NewDisableTOTPHandler(disable, state, terminal),
	}, nil
}

func (s *Shell) Close() error {
	s.enrollment.ClearPendingTOTPSetups()
	s.loginService.ClearTOTPLoginChallenges()
	return s.line.Close()
}

func (s *Shell) Run(ctx context.Context) error {
	readStopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.line.Close()
		case <-readStopped:
		}
	}()
	defer close(readStopped)

	fmt.Fprintln(s.out, "Authentication CLI ready. Run `help` to see available commands.")
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		raw, err := s.line.Readline()
		if ctx.Err() != nil {
			return nil
		}
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
		if !recognizedCommand(command) {
			fmt.Fprintln(s.out, "Unknown command. Run `help` to see available commands.")
			continue
		}
		if err := s.line.SaveHistory(command); err != nil {
			fmt.Fprintln(s.out, "Warning: command history could not be saved.")
		}
		if !knownCommand(s.state, command) {
			if s.state.IsAuthenticated() {
				fmt.Fprintln(s.out, "You are already logged in. Log out before using this command.")
			} else {
				fmt.Fprintln(s.out, "You must log in before using this command.")
			}
			continue
		}

		switch command {
		case "help":
			s.printHelp()
		case "exit":
			return nil
		case "register":
			if err := s.register.Handle(ctx); err != nil {
				if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
					fmt.Fprintln(s.out, "Registration cancelled.")
					continue
				}
				return fmt.Errorf("register command: %w", err)
			}
		case "login":
			if err := s.login.Handle(ctx); err != nil {
				if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
					fmt.Fprintln(s.out, "Login cancelled.")
					continue
				}
				return fmt.Errorf("login command: %w", err)
			}
		case "whoami":
			s.whoami.Handle(ctx)
		case "logout":
			s.logout.Handle(ctx)
		case "enable-2fa":
			if err := s.enableTOTP.Handle(ctx); err != nil {
				if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
					fmt.Fprintln(s.out, "Two-factor setup cancelled.")
					continue
				}
				return fmt.Errorf("enable-2fa command: %w", err)
			}
		case "disable-2fa":
			if err := s.disableTOTP.Handle(ctx); err != nil {
				if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
					fmt.Fprintln(s.out, "Disable two-factor authentication cancelled.")
					continue
				}
				return fmt.Errorf("disable-2fa command: %w", err)
			}
		}
	}
}

func recognizedCommand(command string) bool {
	return slices.Contains(loggedOutCommands, command) || slices.Contains(loggedInCommands, command)
}

func (s *Shell) printHelp() {
	fmt.Fprintln(s.out, "Available commands:")
	for _, command := range AvailableCommands(s.state) {
		fmt.Fprintf(s.out, "  %-12s %s\n", command, commandDescription(command))
	}
}

func commandDescription(command string) string {
	switch command {
	case "register":
		return "Create a user account."
	case "login":
		return "Authenticate with a username, password, and TOTP when enabled."
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
