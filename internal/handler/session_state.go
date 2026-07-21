package handler

type SessionState interface {
	SessionToken() string
	SetSession(rawToken string)
	ClearSession()
}
