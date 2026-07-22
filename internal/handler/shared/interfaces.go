package shared

type ISessionState interface {
	IsAuthenticated() bool
	SessionToken() string
	SetSession(rawToken string)
	ClearSession()
}

type ITerminal interface {
	Prompt(label string) (string, error)
	PromptSecret(label string) (string, error)
	Println(message string)
}

type IQRRenderer interface {
	Render(content string)
}
