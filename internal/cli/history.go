package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func prepareHistory(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create history file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close history file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure history file: %w", err)
	}
	return nil
}

func knownCommand(state *State, command string) bool {
	return slices.Contains(AvailableCommands(state), command)
}
