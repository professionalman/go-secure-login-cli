package cli

import "sync"

// State stores authentication material that is allowed to exist only in the
// running CLI process.
type State struct {
	mu              sync.RWMutex
	rawSessionToken string
}

func (s *State) IsAuthenticated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rawSessionToken != ""
}

func (s *State) SetSession(rawToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawSessionToken = rawToken
}

func (s *State) ClearSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawSessionToken = ""
}
