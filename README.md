# Authentication CLI

A containerized, interactive authentication application written in Go. The completed application will support registration, password login, optional TOTP two-factor authentication, account lockout, and database-backed sessions stored in SQLite.

## Current milestone

Milestone 5 provides confirmed TOTP enrollment in addition to registration, password login, temporary lockout, and persistent sessions:

- TOTP provisioning with configurable issuer, period, skew, and six- or eight-digit codes
- compact terminal QR rendering and explicit provisioning URI output
- process-local pending enrollment that expires after the configured timeout
- confirmation with a valid current authenticator code before persistence
- AES-256-GCM encryption with a new nonce for every stored TOTP secret
- cancellation on blank input or interrupted prompts
- pending-state replacement, expiry, success, cancellation, and shutdown cleanup
- persistent failed-login thresholds and temporary account locks
- random database-backed sessions whose raw tokens remain process-local

TOTP login and the secure `disable-2fa` flow are implemented in Milestone 6. Existing sessions remain valid after enrollment.

> **Milestone 5 limitation:** after enabling 2FA and logging out, that account cannot complete a new login until Milestone 6 is implemented. Use a disposable test account or keep the current session active when evaluating enrollment.

## Configuration

Create a local environment file and replace the sample encryption key:

```bash
cp .env.example .env
openssl rand -base64 32
```

Place the generated value in `TOTP_ENCRYPTION_KEY_BASE64`. The application refuses to start with a missing, malformed, or incorrectly sized key. Losing or changing this key makes existing encrypted TOTP secrets unusable.

The checked-in `.env.example` uses container paths. For a direct local run, set `DATABASE_PATH=data/auth.db` and `HISTORY_PATH=data/.auth-cli-history` in the process environment.

Relevant authentication settings include:

```env
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=15m
SESSION_TIMEOUT=30m

TOTP_ISSUER=InternshipAuthCLI
TOTP_PERIOD=30
TOTP_SKEW=1
TOTP_DIGITS=6
TOTP_SETUP_TIMEOUT=10m
TOTP_ENCRYPTION_KEY_BASE64=replace-with-base64-encoded-32-byte-key
```

Durations and thresholds must be positive. TOTP digits must be either 6 or 8.

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

To enroll an authenticated account in TOTP:

1. Run `enable-2fa`.
2. Scan the terminal QR code or import the displayed provisioning URI.
3. Enter the current authenticator code at the hidden prompt.
4. Retry an invalid code, or press Enter/Ctrl+C to cancel.

The provisioning URI contains the TOTP secret and is displayed intentionally. It is never written to command history or application logs.

Commands available while logged out:

- `register`
- `login`
- `help`
- `exit`

Commands available while logged in:

- `whoami` — validate the current database session and display account details
- `enable-2fa` — start and confirm TOTP enrollment
- `logout` — revoke the current session and clear local authentication state
- `disable-2fa` — reserved for Milestone 6
- `help`
- `exit`

Commands accept no arguments. Passwords and TOTP codes are collected through hidden prompts.

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

The authentication service owns enrollment state and confirmation rules. A clock-injected TOTP service owns provisioning and code validation. AES-GCM is isolated behind an encryption dependency. The session service uses a unit of work so updating login state and inserting a session commit or roll back together. Repositories own SQL and timestamp parsing; handlers own prompts, QR output, messages, command authorization, and in-memory CLI state.

## Security notes

- TOTP secrets are persisted only after a correct confirmation code.
- Stored TOTP secrets use AES-256-GCM with a fresh nonce and Base64 `nonce || ciphertext` encoding.
- Pending plaintext TOTP secrets exist only in process memory, expire after ten minutes by default, and are cleared on replacement, success, cancellation, or shutdown.
- The provisioning URI contains the secret, so it is displayed only during the interactive setup flow.
- Passwords and TOTP codes are read without terminal echo.
- Passwords are hashed with bcrypt before persistence.
- Unknown usernames and wrong passwords produce the same credential error; unknown-user attempts still perform bcrypt work.
- Known-user password failures share a persistent counter and trigger a temporary lock at the configured threshold.
- Raw session tokens are never printed or stored in SQLite. Only lowercase SHA-256 hashes are persisted.
- Session expiry is absolute, and protected commands query SQLite every time.
- Enabling 2FA does not revoke existing sessions.
- Usernames are normalized and protected by a unique database index.
- Secrets are supplied through environment variables and are never committed.
- Command history is saved manually and contains recognized command names only.
- The container runs as an unprivileged user.
- SQLite databases, history, binaries, and local environment files are ignored by Git and Docker build context.
