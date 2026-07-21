package cli

import "github.com/chzyer/readline"

var loggedOutCommands = []string{"register", "login", "help", "exit"}
var loggedInCommands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}

// Completer selects command candidates from the current authentication state.
type Completer struct {
	state *State
}

func NewCompleter(state *State) *Completer {
	return &Completer{state: state}
}

func (c *Completer) Do(line []rune, pos int) ([][]rune, int) {
	items := make([]readline.PrefixCompleterInterface, 0, len(AvailableCommands(c.state)))
	for _, command := range AvailableCommands(c.state) {
		items = append(items, readline.PcItem(command))
	}
	return readline.NewPrefixCompleter(items...).Do(line, pos)
}

func AvailableCommands(state *State) []string {
	commands := loggedOutCommands
	if state != nil && state.IsAuthenticated() {
		commands = loggedInCommands
	}
	result := make([]string, len(commands))
	copy(result, commands)
	return result
}
