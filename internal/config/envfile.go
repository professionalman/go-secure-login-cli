package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadEnvFile loads a simple KEY=VALUE file without overriding variables that
// are already present in the process environment.
func LoadEnvFile(path string) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open environment file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return fmt.Errorf("invalid environment entry %q", line)
		}
		if _, exists := os.LookupEnv(name); exists {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("set environment variable %s: %w", name, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read environment file: %w", err)
	}
	return nil
}
