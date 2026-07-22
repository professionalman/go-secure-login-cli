# Authentication CLI

A Go command-line authentication project using PostgreSQL, Redis, Docker, database-backed sessions, account lockout, and optional TOTP two-factor authentication.

This is a terminal application, not an HTTP API. You use commands such as `register`, `login`, and `whoami`.

## Features

- Registration and bcrypt password hashing
- Password login with generic invalid-credential responses
- Redis-backed failed-attempt counting and temporary lockout
- Optional TOTP two-factor authentication
- Random session tokens with only SHA-256 hashes stored in PostgreSQL
- Multiple independent sessions for the same user
- Per-session logout and absolute session expiration
- State-aware tab completion and command-name-only history
- Embedded PostgreSQL migrations
- Persistent PostgreSQL, Redis, and CLI-history Docker volumes

## Requirements

The easiest way to run the project is with Docker.

For Docker:

- Git
- Docker Desktop on Windows or macOS, or Docker Engine on Linux
- Docker Compose v2

For a native run:

- Go 1.26 or newer
- PostgreSQL and Redis, which may still run through Docker

Check Docker:

```text
docker --version
docker compose version
```

Run all commands from the project directory containing `docker-compose.yml`.

## Demonstration TOTP encryption key

The application requires a Base64-encoded 32-byte key to encrypt TOTP secrets.

You may use this public key to check the assignment locally:

```env
TOTP_ENCRYPTION_KEY_BASE64=tt+dC5vhHj4ghzUFiP62J31NevdTWqB7qP0merFdzu8=
```

This key is intentionally public. Do not use it in production. Anyone with this key and the database could decrypt stored TOTP secrets.

Generate a private key on Windows PowerShell:

```powershell
$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$rng.Dispose()
[Convert]::ToBase64String($keyBytes)
```

Generate a private key on macOS or Linux:

```bash
openssl rand -base64 32
```

## Run with Docker on Windows

Open PowerShell in the project directory:

```powershell
cd C:\path\to\go-secure-login-cli
```

Create the Docker environment file:

```powershell
Copy-Item .env.docker.example .env.docker
```

Build the application and start PostgreSQL and Redis:

```powershell
docker compose build app
docker compose up -d postgres redis
```

Open the CLI:

```powershell
docker compose run --rm app
```

## Run with Docker on macOS or Linux

Open a terminal in the project directory:

```bash
cd /path/to/go-secure-login-cli
```

Create the Docker environment file:

```bash
cp .env.docker.example .env.docker
```

Build the application and start PostgreSQL and Redis:

```bash
docker compose build app
docker compose up -d postgres redis
```

Open the CLI:

```bash
docker compose run --rm app
```

Both operating systems should now show:

```text
Authentication CLI ready. Run `help` to see available commands.
auth-cli>
```

## First-time walkthrough

Show available commands:

```text
help
```

Create a user:

```text
register
```

Username rules:

- 3 to 50 characters by default
- Converted to lowercase and trimmed
- Starts with a lowercase letter or number
- Remaining characters may include lowercase letters, numbers, dots, underscores, and hyphens

Password rules:

- 8 to 72 UTF-8 bytes by default
- Not trimmed or converted to lowercase
- Confirmation must match exactly
- `ABcd1234` is valid with the default settings

Password input is hidden.

Log in:

```text
login
```

After login, try:

```text
whoami
enable-2fa
logout
```

Press Tab at an empty prompt to see commands available in the current login state.

## Commands

Logged out:

| Command | Purpose |
| --- | --- |
| `help` | Show available commands |
| `register` | Create an account |
| `login` | Log in with password and TOTP when enabled |
| `exit` | Close the CLI |

Logged in:

| Command | Purpose |
| --- | --- |
| `help` | Show available commands |
| `whoami` | Validate the session and show user information |
| `enable-2fa` | Set up TOTP authentication |
| `disable-2fa` | Disable TOTP after password and code verification |
| `logout` | Revoke only this terminal's session |
| `exit` | Close the CLI and clear its local session token |

Commands take no command-line arguments. The CLI prompts separately for usernames, passwords, and codes, so secrets do not enter command history.

## Try TOTP two-factor authentication

Install Google Authenticator, Microsoft Authenticator, Authy, or another TOTP-compatible app.

1. Register and log in.
2. Run `enable-2fa`.
3. Scan the QR code or use the displayed provisioning URI.
4. Enter the current six-digit authenticator code.
5. Run `logout`.
6. Run `login` again.
7. Enter the password and then the current TOTP code.

The encryption key is not the six-digit authenticator code. It encrypts the saved TOTP secret.

Keep the same `TOTP_ENCRYPTION_KEY_BASE64` after enabling 2FA. Changing or losing it makes existing encrypted TOTP secrets unreadable.

## Running multiple CLI instances with Docker

Each `docker compose run` command creates an independent CLI process. All processes share PostgreSQL and Redis but keep separate raw session tokens and authentication state.

Start shared services:

```text
docker compose up -d postgres redis
```

Open terminal 1:

```text
docker compose run --rm app
```

Open terminal 2:

```text
docker compose run --rm app
```

Suggested check:

1. Register in terminal 1.
2. Log in as the same user in terminals 1 and 2.
3. Run `whoami` in both.
4. Log out in terminal 1.
5. Run `whoami` in terminal 2; it should remain logged in.
6. Cause failed logins in one terminal and confirm Redis enforces the block in another.

Separate history paths stop command histories from mixing. They do not create sessions. Every successful login creates its own token and PostgreSQL session row.

Shared between terminals:

- PostgreSQL users and hashed sessions
- Redis failure counters and block state
- Docker volumes

Not shared between terminals:

- Raw session tokens
- Process login state and tab completion
- Instance-specific history
- Pending TOTP setup and login challenges

## Run natively on Windows

Create both environment files:

```powershell
Copy-Item .env.docker.example .env.docker
Copy-Item .env.local.example .env.local
```

Start the databases and run Go:

```powershell
docker compose up -d postgres redis
go run ./cmd/cli
```

For independent histories, use separate PowerShell windows:

```powershell
$env:HISTORY_PATH = "data/.auth-cli-history-1"
go run ./cmd/cli
```

Use `.auth-cli-history-2` in the second window.

## Run natively on macOS or Linux

Create both environment files:

```bash
cp .env.docker.example .env.docker
cp .env.local.example .env.local
```

Start the databases and run Go:

```bash
docker compose up -d postgres redis
go run ./cmd/cli
```

For independent histories:

```bash
HISTORY_PATH=data/.auth-cli-history-1 go run ./cmd/cli
```

Use `.auth-cli-history-2` in the second terminal.

## Docker URL versus local URL

Inside Docker, Compose services use service names:

```env
DATABASE_URL=postgres://auth_cli:change-this-postgres-password@postgres:5432/auth_cli?sslmode=disable
REDIS_URL=redis://redis:6379/0
```

A Go process running directly on your computer uses `localhost`:

```env
DATABASE_URL=postgres://auth_cli:change-this-postgres-password@localhost:5432/auth_cli?sslmode=disable
REDIS_URL=redis://localhost:6379/0
```

Use `postgres` and `redis` in `.env.docker`. Use `localhost` in `.env.local`. The PostgreSQL username, password, and database name must match in both files.

## Environment files

- `.env.docker` is loaded by Docker Compose.
- `.env.local` is loaded by a natively executed Go application.
- Real environment files are ignored by Git.
- Committed `.example` files are safe templates.

| Variable | Example | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL URL | Database connection |
| `REDIS_URL` | Redis URL | Shared lockout state |
| `HISTORY_PATH` | `/app/data/.auth-cli-history` | Command-name history |
| `MIN_USERNAME_LENGTH` | `3` | Minimum username length |
| `MAX_USERNAME_LENGTH` | `50` | Maximum username length |
| `MIN_PASSWORD_LENGTH` | `8` | Minimum password byte length |
| `MAX_PASSWORD_LENGTH` | `72` | Maximum bcrypt-safe byte length |
| `BCRYPT_COST` | `12` | bcrypt work factor |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failures before lockout |
| `ACCOUNT_LOCKOUT_DURATION` | `15m` | Lockout duration |
| `SESSION_TIMEOUT` | `30m` | Absolute session lifetime |
| `TOTP_ENCRYPTION_KEY_BASE64` | Required | TOTP encryption key |

All configuration is validated at startup.

## Session and security behavior

A successful login stores the raw token only in that CLI process:

```text
AUTH_CLI_SESSION_TOKEN
```

PostgreSQL stores only its lowercase SHA-256 hash. Every protected command hashes and validates the process token. Logout, expiration, authorization failure, or shell exit removes the local token.

Passwords are stored as bcrypt hashes. TOTP secrets are encrypted with AES-256-GCM. Redis stores failed-attempt counters and temporary blocks.

## Persistence and reset

Stop services while keeping all Docker volume data:

```text
docker compose down
```

Restart later:

```text
docker compose up -d postgres redis
docker compose run --rm app
```

Permanently delete users, sessions, Redis data, and histories:

```text
docker compose down -v
```

Warning: `docker compose down -v` cannot be undone.

Clear only Redis lockouts during local testing:

```text
docker compose exec redis redis-cli FLUSHDB
```

## Tests and generated mocks

Repository tests use `go-sqlmock`, so they do not connect to PostgreSQL. Redis repository tests use generated client mocks and do not connect to Redis.

```text
go generate ./...
go test ./...
go vet ./...
go build ./cmd/cli
docker build .
```

### Checking code coverage

**Current measured coverage: 13.2% of statements** (measured on July 22, 2026).

This is overall application coverage excluding generated mock packages. The current tests focus on PostgreSQL repositories, Redis lockout behavior, transactions, and migrations; handlers and services are not yet covered.


Generated `mocks` packages are excluded from the coverage report because generated code is not application logic and including it would distort the useful percentage.

On Windows PowerShell, run these commands from the project directory:

```powershell
$packages = go list ./... | Where-Object { $_ -notmatch '/mocks$' }
go test $packages "-coverprofile=coverage.out"
go tool cover "-func=coverage.out"
go tool cover "-html=coverage.out" "-o=coverage.html"
Start-Process .\coverage.html
```

On macOS or Linux:

```bash
packages=$(go list ./... | grep -v '/mocks$')
go test $packages -coverprofile=coverage.out
go tool cover -func=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

Open the HTML report with:

```bash
# macOS
open coverage.html

# Linux
xdg-open coverage.html
```

The commands create:

- `coverage.out`: machine-readable Go coverage data, ignored by Git.
- `coverage.html`: a line-by-line browser report. Green statements were executed; red statements were not.

For a quick package-by-package percentage without creating files, including generated mock packages:

```text
go test ./... -cover
```

## Architecture

```text
Interactive CLI -> Handlers -> Services -> Repository interfaces -> PostgreSQL/Redis
```

```text
internal/
  handler/
    auth/
    session/
    shared/
    totp/
  service/
    auth/
    session/
    totp/
  repository/
    user/
    session/
    transaction/
    loginsecurity/
  database/
    postgres/
```

Handlers own terminal input and output. Services own authentication rules. Repositories own PostgreSQL and Redis access.

## Troubleshooting

### Missing or invalid TOTP encryption key

Copy the demonstration value into the environment file used by your run:

```env
TOTP_ENCRYPTION_KEY_BASE64=tt+dC5vhHj4ghzUFiP62J31NevdTWqB7qP0merFdzu8=
```

Restart the CLI.

### A user becomes locked quickly

Check `MAX_LOGIN_ATTEMPTS`. With `5`, the fifth failure starts the temporary block. Existing Redis blocks remain until their TTL expires.

For local testing only:

```text
docker compose exec redis redis-cli FLUSHDB
```

### Native Go cannot connect

Check services:

```text
docker compose ps
```

Native runs use `localhost` in `.env.local`. Docker runs use `postgres` and `redis` in `.env.docker`.

### Port 5432 or 6379 is already in use

Stop the existing PostgreSQL or Redis service, or change the published Compose port and the matching URL in `.env.local`.

### Reset everything

```text
docker compose down -v
docker compose up -d postgres redis
docker compose run --rm app
```
