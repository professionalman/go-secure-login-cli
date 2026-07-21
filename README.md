# Authentication CLI

A containerized, interactive authentication application written in Go. It supports registration, password login, optional TOTP two-factor authentication, temporary account lockout, and database-backed sessions stored in SQLite.

## Current milestone

Milestone 6 completes the authentication lifecycle:

- secure registration and normalized usernames
- password login with generic credential errors and dummy-hash work for unknown users
- persistent failed-login thresholds shared by password and TOTP login failures
- temporary account lockout with precise expiry behavior
- random, database-backed sessions with absolute expiry
- confirmed TOTP enrollment with terminal QR and provisioning URI output
- AES-256-GCM encryption of stored TOTP secrets
- opaque, process-local TOTP login challenges that expire after the configured timeout
- password-and-TOTP reauthentication before disabling 2FA
- atomic clearing of the enabled flag and encrypted TOTP secret

Pending enrollment and login challenge state is process-local and cleared on cancellation, success, expiry, or application shutdown. Enabling or disabling 2FA does not revoke existing sessions.

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
TOTP_CHALLENGE_TIMEOUT=5m
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

The provisioning URI contains the TOTP secret and is displayed intentionally. It is never written to command history or application logs. Subsequent logins first verify the password and then prompt for a current authenticator code. The password step creates only an opaque, five-minute in-memory challenge; no session exists until the code succeeds.

To disable TOTP, run `disable-2fa` while logged in and enter the current password and authenticator code at the hidden prompts. Failed disable reauthentication does not affect login-lockout counters, and a successful disable leaves the current session valid.

Commands available while logged out:

- `register`
- `login`
- `help`
- `exit`

Commands available while logged in:

- `whoami` - validate the current database session and display account details
- `enable-2fa` - start and confirm TOTP enrollment
- `disable-2fa` - disable TOTP after password and code reauthentication
- `logout` - revoke the current session and clear local authentication state
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

Authentication services own validation, lockout, TOTP enrollment, opaque login challenges, disable reauthentication, and login orchestration. A clock-injected TOTP service owns provisioning and code validation. AES-GCM is isolated behind an encryption dependency. The session service uses a unit of work so updating login state and inserting a session commit or roll back together. Repositories own SQL and timestamp parsing; handlers own prompts, QR output, messages, command authorization, and in-memory CLI state.

## Security notes

- TOTP secrets are persisted only after a correct enrollment confirmation code.
- Stored TOTP secrets use AES-256-GCM with a fresh nonce and Base64 `nonce || ciphertext` encoding.
- Pending plaintext enrollment secrets exist only in process memory and expire after ten minutes by default.
- TOTP login challenges contain only a user ID and expiry, are opaque to handlers, are single-use on success, and expire after five minutes by default.
- Passwords and TOTP codes are read without terminal echo.
- Passwords are hashed with bcrypt before persistence.
- Unknown usernames and wrong passwords produce the same credential error; unknown-user attempts still perform bcrypt work.
- Wrong passwords and wrong login TOTP codes share one persistent failure counter and lock threshold.
- Login failures reset only after all required factors succeed and the session transaction commits.
- Disable-flow reauthentication failures do not modify login-lockout counters.
- Raw session tokens are never printed or stored in SQLite. Only lowercase SHA-256 hashes are persisted.
- Session expiry is absolute, and protected commands query SQLite every time.
- Enabling or disabling 2FA does not revoke existing sessions.
- Usernames are normalized and protected by a unique database index.
- Secrets are supplied through environment variables and are never committed.
- Command history is saved manually and contains recognized command names only.
- The container runs as an unprivileged user.
- SQLite databases, history, binaries, and local environment files are ignored by Git and Docker build context.
