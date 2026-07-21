package cli

import (
	"slices"
	"testing"
)

func TestAvailableCommandsByState(t *testing.T) {
	state := &State{}
	if got := AvailableCommands(state); !slices.Equal(got, loggedOutCommands) {
		t.Fatalf("logged-out commands = %v, want %v", got, loggedOutCommands)
	}

	state.SetSession("raw-token-kept-in-memory")
	if got := AvailableCommands(state); !slices.Equal(got, loggedInCommands) {
		t.Fatalf("logged-in commands = %v, want %v", got, loggedInCommands)
	}

	state.ClearSession()
	if state.IsAuthenticated() {
		t.Fatal("state remained authenticated after ClearSession()")
	}
}

func TestCompleterReturnsCandidateForPrefix(t *testing.T) {
	completer := NewCompleter(&State{})
	candidates, _ := completer.Do([]rune("lo"), 2)
	if len(candidates) == 0 {
		t.Fatal("completion for logged-out prefix \"lo\" returned no candidates")
	}
}
