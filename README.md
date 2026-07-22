# Authentication CLI

A containerized Go command-line authentication application with PostgreSQL persistence, Redis-backed account lockout, database-backed sessions, and optional TOTP two-factor authentication.

## Features

- Username normalization and validation
- bcrypt password hashing
- Generic invalid-credential responses
- Optional TOTP enrollment with terminal QR rendering
- Password-first TOTP login challenges
- Redis-backed failed-attempt counters and temporary account blocking
- Multiple independent sessions for the same user
- Random session tokens stored in PostgreSQL only as SHA-256 hashes
- Absolute session expiry and per-session logout
- State-aware tab completion
- Command-name-only history
- Embedded transactional PostgreSQL migrations
- Docker Compose services with persistent PostgreSQL, Redis, and history volumes

## Architecture

The dependency direction is:

~~~text
Interactive CLI -> Handlers -> Services -> Repository interfaces -> PostgreSQL/Redis
~~~

Code is grouped by entity inside each layer:

~~~text
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
~~~

There is one authentication service, one session service, and one TOTP service. PostgreSQL stores durable users and sessions. Redis stores shared, expiring login-security state.

## Requirements

For Docker execution:

- Docker 27+
- Docker Compose 2.29+

For native execution:

- Go 1.26+
- The PostgreSQL and Redis Docker services, or equivalent locally installed services

## Environment files

Docker and local runs intentionally use separate files:

- `.env.docker`: loaded automatically by every Compose service
- `.env.local`: loaded automatically by the native Go application when present

Only examples are committed:

- `.env.docker.example`
- `.env.local.example`

Create the real files:

~~~powershell
Copy-Item .env.docker.example .env.docker
Copy-Item .env.local.example .env.local
~~~

Generate one 32-byte TOTP encryption key:

~~~powershell
$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$rng.Dispose()
[Convert]::ToBase64String($keyBytes)
~~~

Put the same generated value in both files when Docker and local CLI clients use the same PostgreSQL database:

~~~env
TOTP_ENCRYPTION_KEY_BASE64=generated-base64-value
~~~

Also keep the PostgreSQL password in `.env.local`'s `DATABASE_URL` synchronized with `POSTGRES_PASSWORD` in `.env.docker`.

Never commit either real environment file.

## Quick start with Docker

After creating `.env.docker`:

~~~powershell
docker compose build
docker compose run --rm app
~~~

Compose automatically starts PostgreSQL and Redis when required, waits for their health checks, applies pending migrations, removes expired sessions, and opens the interactive CLI.

Inside the CLI:

~~~text
help
register
login
whoami
enable-2fa
disable-2fa
logout
exit
~~~

## Running Multiple CLI Instances with Docker

Each `docker compose run` command creates a separate CLI process. All instances connect to the same PostgreSQL database and Redis service, while each process owns its own raw session token and authentication state.

Start the shared infrastructure:

~~~powershell
docker compose up -d postgres redis
~~~

Open terminal 1:

~~~powershell
docker compose run --rm -e HISTORY_PATH=/app/data/.auth-cli-history-1 app
~~~

Open terminal 2:

~~~powershell
docker compose run --rm -e HISTORY_PATH=/app/data/.auth-cli-history-2 app
~~~

Additional terminals use another history filename:

~~~powershell
docker compose run --rm -e HISTORY_PATH=/app/data/.auth-cli-history-3 app
~~~

Try the multi-login flow:

1. Run `register` in terminal 1.
2. Run `login` in terminal 1.
3. Run `login` for the same user in terminal 2.
4. Run `whoami` in both terminals.
5. Press Tab and confirm both terminals show logged-in commands.
6. Run `logout` in terminal 1.
7. Confirm terminal 1 now shows logged-out completions.
8. Run `whoami` in terminal 2 and confirm it remains authenticated.
9. Trigger the configured number of failed logins in one terminal and confirm another terminal sees the same temporary block.

Shared across instances:

- PostgreSQL users and session rows
- Redis failed-attempt counters and block state
- Persistent Docker volumes

Not shared across instances:

- Raw session tokens
- Process authentication state
- Tab-completion state
- Instance-specific history files
- Pending TOTP enrollment and login challenges

A logout revokes only the current terminal's session. Other terminal sessions remain valid.

## Native local run

Create both environment files, then start only the shared services:

~~~powershell
docker compose up -d postgres redis
~~~

The local example uses `localhost` rather than Compose service hostnames. Run the native CLI:

~~~powershell
go run ./cmd/cli
~~~

The application automatically loads `.env.local`. Environment variables already present in the process take precedence over values in that file.

To open multiple native clients, run `go run ./cmd/cli` in separate PowerShell windows. Each process has its own `AUTH_CLI_SESSION_TOKEN`, while all clients use the common PostgreSQL and Redis services.

If multiple native clients run simultaneously, give each one a separate history path before starting:

~~~powershell
$env:HISTORY_PATH = 'data/.auth-cli-history-1'
go run ./cmd/cli
~~~

## Session behavior

After successful authentication, the CLI stores the raw token in the process-only environment variable:

~~~text
AUTH_CLI_SESSION_TOKEN
~~~

The variable:

- exists only inside the running CLI process
- is never printed
- is never written to command history
- is removed on logout, expiry, revocation, invalid authorization, or shutdown
- cannot modify the parent PowerShell environment

PostgreSQL stores only `SHA-256(raw token)`. Every protected operation hashes the in-process token and validates the matching database session. SHA-256 is hashing, not encryption; deterministic hashing is required for token lookup. The token itself has 256 bits of random entropy.

## Redis account lockout

Redis stores two namespaced keys per affected user:

- a failed-attempt counter
- an expiring blocked marker

An atomic Lua operation increments failures. At `MAX_LOGIN_ATTEMPTS`, Redis deletes the counter and creates the blocked key with a TTL equal to `ACCOUNT_LOCKOUT_DURATION`.

Password and TOTP login failures use the same counter. Successful password verification does not reset failures when TOTP is still required. State resets only after complete authentication. If Redis is unavailable, login fails closed so lockout cannot be bypassed.

## PostgreSQL persistence

The schema uses:

- `VARCHAR` columns with bounded sizes
- `TIMESTAMPTZ` for all persisted times
- explicit unique and lookup indexes
- a TOTP consistency check
- foreign-key cascade from users to sessions

Embedded migrations run in version order. A PostgreSQL advisory lock prevents two CLI processes from applying migrations concurrently.

## TOTP behavior

Run `enable-2fa` while logged in:

1. The CLI generates a per-user TOTP secret.
2. It displays a QR code and provisioning URI.
3. The user confirms a current code.
4. The application encrypts the secret with AES-256-GCM before saving it.

The encryption key is external configuration. Changing or losing it makes existing encrypted TOTP secrets unreadable.

Pending setup and login challenges are process-local. Complete them in the same CLI instance where they began.

## Configuration

| Variable | Docker example | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL Compose hostname | PostgreSQL connection string |
| `REDIS_URL` | Redis Compose hostname | Redis connection string |
| `HISTORY_PATH` | `/app/data/.auth-cli-history` | Recognized-command history |
| `MIN_USERNAME_LENGTH` | `3` | Minimum normalized username length |
| `MAX_USERNAME_LENGTH` | `50` | Maximum normalized username length |
| `MIN_PASSWORD_LENGTH` | `8` | Minimum password byte length |
| `MAX_PASSWORD_LENGTH` | `72` | Maximum bcrypt-safe byte length |
| `BCRYPT_COST` | `12` | bcrypt cost |
| `MAX_LOGIN_ATTEMPTS` | `5` | Redis lockout threshold |
| `ACCOUNT_LOCKOUT_DURATION` | `15m` | Redis block TTL |
| `SESSION_TIMEOUT` | `30m` | Absolute session lifetime |
| `TOTP_SETUP_TIMEOUT` | `10m` | Pending setup lifetime |
| `TOTP_CHALLENGE_TIMEOUT` | `5m` | Pending login challenge lifetime |
| `TOTP_ENCRYPTION_KEY_BASE64` | no default | Base64-encoded 32-byte AES key |

All configuration is validated at startup.

## Volume lifecycle

Stop containers but preserve users, sessions, lockouts, and histories:

~~~powershell
docker compose down
~~~

Permanently delete all PostgreSQL, Redis, and CLI-history volumes:

~~~powershell
docker compose down -v
~~~

The `-v` operation is destructive and cannot be undone.

## Validation commands

~~~powershell
gofmt -w (rg --files -g '*.go')
go vet ./...
go build -o bin/auth-cli.exe ./cmd/cli
docker compose config
docker build .
~~~
