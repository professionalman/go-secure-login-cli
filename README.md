# Authentication CLI

A containerized Go command-line application for account registration, password login, optional TOTP two-factor authentication, temporary account lockout, and database-backed sessions.

The project is intentionally small enough to understand as an internship assignment. It uses a three-layer design, SQLite persistence, standard Go wiring, and focused tests without a web framework or dependency-injection container.

## Features

- normalized, unique usernames
- bcrypt password hashing
- password login with generic credential errors
- optional TOTP enrollment with a terminal QR code
- password-first TOTP login challenges
- temporary account lockout shared across password and login-code failures
- random session tokens stored in SQLite only as SHA-256 hashes
- absolute session expiry and revocation on logout
- secure 2FA disable flow requiring the current password and TOTP code
- embedded, transactional SQLite migrations
- state-aware completion and command history containing command names only
- non-root Docker image and persistent Compose volume
- graceful Ctrl+C/Ctrl+D, `exit`, and container shutdown handling

## Requirements

Choose either:

- Docker 27+ with Docker Compose, or
- Go 1.26+ for a local run

## Quick start with Docker

Copy the example configuration and generate a 32-byte encryption key:

```bash
cp .env.example .env
openssl rand -base64 32
```

Replace `TOTP_ENCRYPTION_KEY_BASE64` in `.env` with the generated value, then run:

```bash
docker compose build
docker compose run --rm app
```

The first start creates `/app/data/auth.db`, applies migrations, and removes expired sessions. Run `help` inside the CLI to see commands available in the current login state.

## Local run

The binary reads process environment variables; it does not automatically load `.env`. In PowerShell:

```powershell
$env:TOTP_ENCRYPTION_KEY_BASE64 = '<base64-encoded-32-byte-key>'
$env:DATABASE_PATH = 'data/auth.db'
$env:HISTORY_PATH = 'data/.auth-cli-history'
go run ./cmd/cli
```

## Typical command flow

```text
register
login
enable-2fa
whoami
logout
login          # now asks for password and authenticator code
disable-2fa    # asks for current password and authenticator code
logout
exit
```

Logged-out commands are `register`, `login`, `help`, and `exit`.

Logged-in commands are `whoami`, `enable-2fa`, `disable-2fa`, `logout`, `help`, and `exit`.

Commands accept no arguments. Passwords and TOTP codes are collected through hidden prompts. Press Enter at an optional confirmation prompt or Ctrl+C to cancel the current interaction.

### Enabling 2FA

1. Log in and run `enable-2fa`.
2. Scan the terminal QR code or import the displayed provisioning URI.
3. Enter the current authenticator code to confirm enrollment.

The provisioning URI contains the TOTP secret and is intentionally displayed once during setup. It is not written to command history or application logs.

### Disabling 2FA

Run `disable-2fa` while logged in. The command requires the current password and TOTP code. Reauthentication failures do not change login-lockout counters, and disabling 2FA does not revoke the current session.

## Configuration

Non-sensitive values use the defaults shown in `.env.example`:

| Setting | Default | Purpose |
| --- | --- | --- |
| `DATABASE_PATH` | `/app/data/auth.db` | SQLite database path |
| `HISTORY_PATH` | `/app/data/.auth-cli-history` | recognized-command history path |
| `MIN_USERNAME_LENGTH` / `MAX_USERNAME_LENGTH` | `3` / `50` | username limits |
| `MIN_PASSWORD_LENGTH` / `MAX_PASSWORD_LENGTH` | `8` / `72` | bcrypt-safe password byte limits |
| `BCRYPT_COST` | `12` | bcrypt work factor |
| `MAX_LOGIN_ATTEMPTS` | `5` | shared password/TOTP failure threshold |
| `ACCOUNT_LOCKOUT_DURATION` | `15m` | temporary lock duration |
| `SESSION_TIMEOUT` | `30m` | absolute session lifetime |
| `TOTP_ISSUER` | `InternshipAuthCLI` | authenticator display name |
| `TOTP_PERIOD` / `TOTP_SKEW` | `30` / `1` | code period and accepted adjacent windows |
| `TOTP_DIGITS` | `6` | supported values are 6 or 8 |
| `TOTP_SETUP_TIMEOUT` | `10m` | pending enrollment lifetime |
| `TOTP_CHALLENGE_TIMEOUT` | `5m` | password-first login challenge lifetime |

`TOTP_ENCRYPTION_KEY_BASE64` is required and has no default. It must decode to exactly 32 bytes.

## Architecture

```text
Interactive CLI -> Handlers -> Services -> Repository interfaces -> SQLite
```

- Handlers own prompts, messages, command authorization, and in-memory CLI state.
- Services own validation, authentication rules, lockout, TOTP workflows, and session lifecycle.
- Repositories own SQL, timestamp parsing, and persistence error translation.

Dependencies such as the clock, password verification, token generation, TOTP validation, encryption, and repositories are passed into services so important behavior can be tested deterministically.

Successful authentication uses a unit of work: session insertion, failure-counter reset, lock clearing, and `last_login_at` update either commit together or roll back together.

## Security decisions

- Usernames are trimmed, lowercased, validated, and protected by a unique index.
- Passwords are never trimmed and are limited to 8-72 UTF-8 bytes before bcrypt hashing.
- Unknown users still trigger a dummy bcrypt comparison and receive the same error as a wrong password.
- Wrong passwords and wrong login TOTP codes share one persistent failure counter.
- TOTP secrets are encrypted with AES-256-GCM using a fresh nonce for each encryption.
- TOTP login challenges are opaque, process-local, single-use on success, and contain only a user ID and expiry.
- Raw session tokens remain in process memory and are never printed or stored in SQLite.
- Protected commands validate the database session each time; expiry is absolute rather than sliding.
- SQLite enables foreign keys, a five-second busy timeout, one open connection, and WAL mode for file databases.
- Pending enrollment and login challenges are cleared on success, cancellation, expiry, or shutdown.

## Persistence and reset warning

Docker Compose stores the database and history in the `auth_data` named volume. This survives container replacement.

Stop containers without deleting data:

```bash
docker compose down
```

Permanently delete all accounts, sessions, 2FA enrollment, and command history:

```bash
docker compose down -v
```

That reset cannot be undone unless the volume was backed up. Changing or losing the encryption key makes existing encrypted TOTP secrets unusable.

## Validation and tests

```bash
go test ./...
go vet ./...
go build ./cmd/cli
docker build -t auth-cli:local .
```

Repository unit tests use `sqlmock`; they do not open SQLite. Migration and service integration tests use isolated temporary SQLite files to verify schema constraints and transaction behavior. GitHub Actions runs tests, vet, the Go build, and the Docker build on pushes and pull requests.

## Assumptions and limitations

- The application is designed for one interactive process using one SQLite database.
- Pending TOTP setup and login challenges do not survive a restart.
- Existing sessions remain valid when 2FA is enabled or disabled.
- Recovery codes, password changes, account recovery, and encryption-key rotation are out of scope.
- Losing the TOTP device or encryption key requires resetting the disposable project data; there is no recovery workflow.
- There is no HTTP API, multi-user server, distributed session coordination, or horizontal scaling.
- Command history stores recognized command names only, not usernames, passwords, TOTP codes, or provisioning URIs.
