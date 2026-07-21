# Authentication CLI

A containerized, interactive authentication application written in Go. The completed application will support registration, password login, optional TOTP two-factor authentication, account lockout, and database-backed sessions stored in SQLite.

## Current milestone

Milestone 4 provides registration, password authentication, persistent sessions, and temporary account lockout:

- normalized unique usernames and bcrypt password hashes
- generic failures for unknown usernames and wrong passwords
- a fixed dummy bcrypt comparison for unknown-user attempts
- configurable failed-login thresholds and lock durations
- persisted failure counts and `locked_until` timestamps
- strict lock expiry: a lock is active only while `locked_until` is later than the current time
- first-failure behavior after lock expiry, starting again from one
- failure-state reset only after complete authentication
- 32-byte random session tokens encoded as unpadded Base64URL
- SHA-256 session-token hashes in SQLite; raw tokens remain process-local
- atomic session creation, login-security reset, and `last_login_at` update
- absolute session expiry and database validation on every protected command
- session revocation on logout
- state-aware commands and completion for logged-out and logged-in users
- hidden credential prompts and command-name-only history

TOTP setup and login are implemented in later milestones. The lockout service is structured so wrong TOTP codes can share the same failure counter when that flow is added.

## Configuration

Create a local environment file and replace the sample encryption key:

```bash
cp .env.example .env
openssl rand -base64 32
```

Place the generated value in `TOTP_ENCRYPTION_KEY_BASE64`. The application refuses to start with a missing, malformed, or incorrectly sized key.

The checked-in `.env.example` uses container paths. For a direct local run, set `DATABASE_PATH=data/auth.db` and `HISTORY_PATH=data/.auth-cli-history` in the process environment.

Account lockout is configured with:

```env
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=15m
```

Both values must be positive. With the defaults, the fifth consecutive failed password attempt locks the account for 15 minutes. Successful complete authentication resets the counter and lock state.

## Run with Docker

```bash
docker compose build
docker compose run --rm app
```

The `auth_data` named volume preserves the database and command history between runs.

To stop the Compose project without deleting data:

```bash
docker compose down
```

To permanently delete the SQLite database and history:

```bash
docker compose down -v
```

## Run locally

Set the required key and local paths, then start the CLI:

```powershell
$env:TOTP_ENCRYPTION_KEY_BASE64 = '<base64-encoded-32-byte-key>'
$env:DATABASE_PATH = 'data/auth.db'
$env:HISTORY_PATH = 'data/.auth-cli-history'
go run ./cmd/cli
```

Start with `register`, then use `login`. Successful authentication shows the username, registration date, MFA status, absolute session expiry, and previous login time without displaying the session token.

Commands available while logged out:

- `register`
- `login`
- `help`
- `exit`

Commands available while logged in:

- `whoami` — validate the current database session and display account details
- `logout` — revoke the current session and clear local authentication state
- `enable-2fa` and `disable-2fa` — reserved for the TOTP milestones
- `help`
- `exit`

Commands accept no arguments. Usernames and passwords are collected through prompts; passwords are hidden.

## Validation

```bash
gofmt -w ./cmd ./internal ./migrations
go test ./...
go vet ./...
go build ./cmd/cli
docker build -t auth-cli:local .
```

## Architecture

The application follows this dependency direction:

```text
Interactive CLI -> Handlers -> Services -> Repository interfaces -> SQLite
```

Registration, login, and lockout rules live in the authentication service. The session service uses a unit of work so updating login state and inserting a session commit or roll back together. Repository implementations own SQL and timestamp parsing. Handlers own prompts, messages, command authorization, and in-memory CLI state.

## Security notes

- Passwords are read without terminal echo and hashed with bcrypt before persistence.
- Unknown usernames and wrong passwords produce the same credential error; unknown-user attempts still perform bcrypt work.
- Known-user password failures share a persistent counter and trigger a temporary lock at the configured threshold.
- Active locks are checked before password verification and do not accumulate additional failures.
- Expired locks restart failure counting from zero; complete authentication performs the durable reset.
- Password success alone will not reset failures once TOTP login is introduced.
- Raw session tokens are never printed or stored in SQLite. Only lowercase SHA-256 hashes are persisted.
- Session expiry is absolute, and protected commands query SQLite every time.
- Logout revokes the database session before clearing the local token.
- Usernames are trimmed, lowercased, validated, and protected by a unique database index.
- Secrets are supplied through environment variables and are never committed.
- The application validates the future AES-256-GCM key at startup even before TOTP enrollment is implemented.
- Command history is saved manually and contains recognized command names only.
- The container runs as an unprivileged user.
- SQLite databases, history, binaries, and local environment files are ignored by Git and Docker build context.
