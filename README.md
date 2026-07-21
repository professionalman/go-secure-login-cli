# Authentication CLI

A containerized, interactive authentication application written in Go. The completed application will support registration, password login, optional TOTP two-factor authentication, account lockout, and database-backed sessions stored in SQLite.

## Current milestone

Milestone 1 provides the application bootstrap:

- validated environment configuration
- SQLite initialization and idempotent embedded migrations
- an interactive shell with `help` and `exit`
- command-only persistent history
- logged-out tab completion
- a non-root multi-stage Docker image and persistent Compose volume

`register` and `login` are listed by the shell but are intentionally implemented in later milestones.

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

## Validation

```bash
gofmt -w ./cmd ./internal ./migrations
go test ./...
go vet ./...
go build ./cmd/cli
docker build -t auth-cli:local .
```

## Architecture

The completed application follows this dependency direction:

```text
Interactive CLI -> Handlers -> Services -> Repository interfaces -> SQLite
```

Milestone 1 establishes configuration, database, migration, and shell packages. Authentication handlers and services are added as vertical slices in later milestones.

## Security notes

- Secrets are supplied through environment variables and are never committed.
- The application validates the future AES-256-GCM key at startup even before TOTP enrollment is implemented.
- Command history is saved manually and contains recognized command names only.
- The container runs as an unprivileged user.
- SQLite databases, history, binaries, and local environment files are ignored by Git and Docker build context.
