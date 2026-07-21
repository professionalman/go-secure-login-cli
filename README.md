# Authentication CLI

A containerized, interactive authentication application written in Go. The completed application will support registration, password login, optional TOTP two-factor authentication, account lockout, and database-backed sessions stored in SQLite.

## Current milestone

Milestone 2 provides the project bootstrap and registration vertical slice:

- validated environment configuration
- SQLite initialization and idempotent embedded migrations
- normalized, unique usernames with a documented safe character set
- hidden password and confirmation prompts
- configurable password-length validation and bcrypt hashing
- friendly duplicate and validation errors
- an interactive shell with `register`, `help`, and `exit`
- command-only persistent history and logged-out tab completion
- a non-root multi-stage Docker image and persistent Compose volume

`login` is listed by the shell but is intentionally implemented in Milestone 3.

## Configuration

Create a local environment file and replace the sample encryption key:

```bash
cp .env.example .env
openssl rand -base64 32
```

Place the generated value in `TOTP_ENCRYPTION_KEY_BASE64`. The application refuses to start with a missing, malformed, or incorrectly sized key.

The checked-in `.env.example` uses container paths. For a direct local run, set `DATABASE_PATH=data/auth.db` and `HISTORY_PATH=data/.auth-cli-history` in the process environment.

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

Run `register`, then enter a username, password, and matching password confirmation. Password values are hidden and never added to command history.

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

Milestone 2 implements registration across every layer while keeping terminal input, business rules, and SQL in separate packages.

## Security notes

- Passwords are read without terminal echo and hashed with bcrypt before persistence.
- Usernames are trimmed, lowercased, validated, and protected by a unique database index.
- Secrets are supplied through environment variables and are never committed.
- The application validates the future AES-256-GCM key at startup even before TOTP enrollment is implemented.
- Command history is saved manually and contains recognized command names only.
- The container runs as an unprivileged user.
- SQLite databases, history, binaries, and local environment files are ignored by Git and Docker build context.
