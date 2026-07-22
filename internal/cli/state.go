package cli

import (
	"os"
	"sync"
)

const SessionTokenEnvironmentVariable = "AUTH_CLI_SESSION_TOKEN"

type EnvironmentSessionState struct {
	mu sync.RWMutex
}

func NewEnvironmentSessionState() *EnvironmentSessionState {
	state := &EnvironmentSessionState{}
	state.ClearSession()
	return state
}

func (s *EnvironmentSessionState) IsAuthenticated() bool {
	return s.SessionToken() != ""
}

func (s *EnvironmentSessionState) SessionToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return os.Getenv(SessionTokenEnvironmentVariable)
}

func (s *EnvironmentSessionState) SetSession(rawToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Setenv(SessionTokenEnvironmentVariable, rawToken)
}

func (s *EnvironmentSessionState) ClearSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Unsetenv(SessionTokenEnvironmentVariable)
}
