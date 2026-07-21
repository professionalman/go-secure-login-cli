package clock

import "time"

// Clock makes time-sensitive authentication behavior deterministic in tests.
type Clock interface {
	Now() time.Time
}

// System uses the host clock.
type System struct{}

func (System) Now() time.Time {
	return time.Now().UTC()
}
