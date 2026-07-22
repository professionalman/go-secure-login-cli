package cli

import (
	"auth-cli/internal/handler/shared"

	"github.com/chzyer/readline"
)

var loggedOutCommands = []string{"register", "login", "help", "exit"}
var loggedInCommands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}

type Completer struct {
	state shared.ISessionState
}

func NewCompleter(state shared.ISessionState) *Completer {
	return &Completer{state: state}
}

func (c *Completer) Do(line []rune, pos int) ([][]rune, int) {
	items := make([]readline.PrefixCompleterInterface, 0, len(AvailableCommands(c.state)))
	for _, command := range AvailableCommands(c.state) {
		items = append(items, readline.PcItem(command))
	}
	return readline.NewPrefixCompleter(items...).Do(line, pos)
}

func AvailableCommands(state shared.ISessionState) []string {
	commands := loggedOutCommands
	if state != nil && state.IsAuthenticated() {
		commands = loggedInCommands
	}
	return append([]string(nil), commands...)
}
