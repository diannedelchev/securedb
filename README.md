# SecureDB Web Client

[![CI](https://github.com/diannedelchev/securedb/actions/workflows/ci.yml/badge.svg)](https://github.com/diannedelchev/securedb/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/diannedelchev/securedb)](https://goreportcard.com/report/github.com/diannedelchev/securedb)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A browser-based SQL client for **PostgreSQL** and **MySQL/MariaDB** that puts a
policy layer between people and production data: encrypted shared credentials,
role-based access, per-environment query guardrails, four-eyes approvals,
just-in-time access windows, result masking and a durable audit trail. Works
from a desktop browser or an iPad with nothing to install.

**Stack:** Go · Fiber v3 · PostgreSQL (app database) · server-rendered HTML · HTMX.
Templates, static assets and migrations are embedded, so a build is one binary.

## Why

Handing out database passwords and a VPN gives every engineer the same
unbounded access, leaves no record of what was run, and makes offboarding a
credential-rotation exercise. SecureDB keeps the real credentials on the
server, decides per statement whether a user may run it, and writes down who
ran what, where, and with which outcome.

## Contents

- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Roles and permissions](#roles-and-permissions)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
- [Deploying for real](#deploying-for-real)
- [Screens](#screens)
- [Project structure](#project-structure)
- [Tests](#tests)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Screenshots

| Sign in | Dashboard |
|---|---|
| ![Sign in](docs/screenshots/login.png) | ![Dashboard](docs/screenshots/dashboard.png) |

| SQL Editor (data masking) | Approval Requests (risk analysis) |
|---|---|
| ![SQL Editor](docs/screenshots/editor.png) | ![Approval Requests](docs/screenshots/approvals.png) |

## Architecture

```
Browser / iPad
   → Go Fiber SSR web app          (templates + HTMX fragments)
      → Control plane services      (auth, policies, approvals, audit)
         → Connector layer          (DBConnector interface)
            → PostgresConnector / MySQLConnector
               → Target databases
```

Database credentials are AES-256-GCM encrypted in the app database, decrypted
just-in-time inside the connector layer, and never sent to the browser.

## Quick start

Prerequisites: Docker and `make`. For the host-run variant, also Go at the
version in `go.mod`.

### Fully containerized

```bash
git clone https://github.com/diannedelchev/securedb.git && cd securedb
make up          # docker compose up --build -d
```

Open **http://localhost:8080** and sign in with the seeded admin account
(**admin@securedb.local / admin1234!**, local evaluation only). The stack
brings up the app and its PostgreSQL database. Sign in as the admin to add a
database connection on **Connections**; creating connections is limited to
the admin and DBA roles.

### App on the host, database in Docker

```bash
make config      # creates config.yaml with a generated encryption key
# Set seed.admin.password in config.yaml before continuing.
make dev         # starts app-db, then runs the app
```

Run `make` with no arguments to list all targets (`test`, `check`, `logs`,
`reset`, …).

### Try the guardrails

Once a connection exists, open the SQL editor and try:

```sql
-- masking: columns matching card/pan, iban, password/secret, national_id/egn
-- come back masked (emails and phones do not)
SELECT * FROM customers;

-- blocked for non-admins: no WHERE clause
DELETE FROM customers;

-- blocked keyword
DROP TABLE payments;

-- on a connection labelled "production", a write from a non-admin account
-- creates an approval request instead of executing
UPDATE customers SET first_name = 'X' WHERE id = 1;
```

Approve it as a second admin/DBA on **Approval Requests** (the detail pane
shows the SQL, an automated risk analysis and a timeline), then run it from
the requester's account with the one-time **Run approved query** button.

## Configuration

Configuration is layered; later sources win:

1. **Built-in defaults**
2. **`config.yaml`** (path via `CONFIG_FILE`, default `./config.yaml`), created
   with `make config`. See [`config.example.yaml`](config.example.yaml) for
   every key: the app database (an existing PostgreSQL server), listen
   address, encryption key, cookie and proxy flags, session lifetimes and the
   seed account.
3. **Environment variables**: `APP_ADDR`, `APP_ENV`, `DATABASE_URL`,
   `APP_ENCRYPTION_KEY`, `COOKIE_SECURE`, `TRUST_PROXY_IP`, `SESSION_TTL`,
   `SESSION_IDLE_TTL`, `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`,
   `SEED_ADMIN_NAME`. The docker-compose stack uses these so a fresh clone
   runs with zero setup.
4. **`app_settings` table** in the app database: runtime-tunable settings
   (session TTL and idle TTL). Seeded from config on first boot, edited
   afterwards on the admin **Settings** page without a restart.

> ⚠️ The `APP_ENCRYPTION_KEY` and admin password in `docker-compose.yml` are
> public and for local evaluation only. Generate your own key with `make key`
> (`openssl rand -hex 32`) before storing any real credential. Anything
> encrypted under the public key can be decrypted by anyone.

**Initial account.** On first boot against an empty database, seeding creates
the roles, per-environment policies, masking rules and a single admin login
from `seed.admin` (or `SEED_ADMIN_*`). A password of at least 8 characters is
required; it is never logged. Once users exist, the seed password is ignored
on later restarts. Create further users on **Users & Roles**; every user can
then change their own password from the sidebar.

## Roles and permissions

A user can hold several roles and gets the union of their capabilities.

| Capability | admin | dba | developer | qa | analyst | auditor |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Run read queries | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Write in development / staging | ✓ | ✓ | ✓ | ✓ | | |
| Write in production | ✓ | approval¹ | approval¹ | | | |
| Bypass blocked keywords, WHERE and multi-statement rules | ✓ | | | | | |
| Create connections | ✓ | ✓ | | | | |
| Edit / delete / test connections | all | all | own² | own² | own² | own² |
| Approve queries and access windows (four-eyes) | ✓ | ✓ | | | | |
| See everyone's approval requests | ✓ | ✓ | | | | ✓ |
| See everyone's query history | ✓ | | | | | ✓ |
| View audit logs | ✓ | ✓ | | | | ✓ |
| Edit security policies, users, settings | ✓ | | | | | |
| Change own password | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

¹ When the production policy has *require approval for writes* enabled
(the default). An active PAM access window on that connection replaces
per-query approval. ² Only for connections they created before creation was
restricted to admins and DBAs. Every user who can query sees every active
connection.

## Security model

**Authentication and sessions**
- Passwords are bcrypt hashed. Sessions are opaque 256-bit cookie tokens with
  only the SHA-256 hash stored server-side; `HttpOnly`, `SameSite=Lax`,
  `Secure` when `cookie_secure` is on; idle and absolute expiry.
- A per-session CSRF token is verified on every state-changing request (form
  field or `X-CSRF-Token`, which HTMX sends automatically).
- Changing a password revokes the user's other sessions. Deactivating a user
  or changing their roles takes effect on their next request.

**Credentials**
- Database and SSH tunnel credentials are AES-256-GCM encrypted with
  `app.encryption_key` and decrypted just-in-time in the connector layer.
  They are never rendered to a template.
- Enabling SSL on a connection requires certificate and hostname verification
  for both engines; untrusted endpoints do not silently connect.
- Optional SSH tunnel per connection (password or private key) with optional
  host-key fingerprint pinning. One SSH session per database connection.

**Query guardrails**
- SQL is parsed with libpg_query (embedded WebAssembly, no CGo) for PostgreSQL
  and TiDB's parser for MySQL. Unparseable or unsupported statements fail
  closed for everyone.
- Reads run in database-enforced read-only transactions, even on writable
  connections. Read-only connections reject writes for every role.
- Per-environment policy: row cap, timeout, blocked keywords, write
  permission, approval requirement, allowed schemas, masking on or off.
  With `allowed_schemas` set, table references must be schema-qualified.
- Approvals bind to the exact requester, connection, database and SQL text,
  execute once, expire after 24 h, and are void if the connection is edited
  after the request. Nobody can approve their own request.
- PAM access windows (15 min to 8 h) are four-eyes approved, auto-expire, are
  revocable, and never bypass hard guardrails.

**Masking and export**
- Masking rules match the parsed source column, so aliases cannot strip a
  mask. Expressions, subqueries, CTEs and other projections whose provenance
  cannot be established are fully redacted.
- CSV/JSON export is policy-gated per environment and audited before the
  download starts, attributed to the originating history record.

**Auditing**
- Every security-relevant action is recorded with user, IP, user agent and
  submitted SQL. Query intent is committed before target SQL starts and the
  outcome is written afterwards, so a crash leaves a visible `running` record
  rather than a silent gap.

**Policy defaults:** row limit 500 (the editor can pick 100, 500 or
Unlimited), timeout 30 s, blocked keywords `DROP, TRUNCATE, ALTER, CREATE,
GRANT, REVOKE`, production writes require approval and production export is
off. All editable per environment in **Security Center**.

## Known limitations

Read these before relying on the app as a control:

- **No login rate limiting or lockout.** Failed sign-ins are audited but not
  throttled. Put a rate limit on `POST /login` at the reverse proxy.
- **No forgotten-password reset.** There is no outbound email. An admin sets
  a temporary password and the user changes it after signing in.
- **SSH host key verification is opt-in.** Without a pinned fingerprint the
  tunnel accepts any bastion key. Pin it for anything but local testing.
- **Masking is not a security boundary.** It does not prevent inference
  through predicates (`WHERE card = '…'`) or target-side views and routines
  that rename data. Use database grants and views for real column-level
  control.
- **Application checks do not replace database grants.** Give each
  connection a target-side account scoped to what its users should reach.
- **Connections are visible to every user who can query.** Per-connection
  permissions are not implemented yet (see Roadmap).
- **A `running` history record means an unconfirmed outcome.** Inspect the
  target before retrying a write; the app never replays SQL on its own.
- **Query cancellation is per instance.** Sessions live in the app database,
  so several instances can share it, but **Stop** only reaches queries
  running on the instance that received the request.
- **Microsoft SQL Server is not supported.** The connector is a stub.

## Deploying for real

The compose file is an evaluation setup. For a deployment that holds real
credentials:

1. **Terminate HTTPS at a reverse proxy** and set `app.cookie_secure: true`,
   otherwise the session cookie is sent over plain HTTP.
2. **Set `app.trust_proxy_ip: true`** when behind a proxy. Client addresses
   are then read from `X-Forwarded-For` for proxies on loopback or private
   networks; without it every audit entry records the proxy's IP.
3. **Generate a unique encryption key** (`make key`) and treat it like a
   master password. It cannot be rotated in place: changing it makes every
   stored credential unreadable. Back it up together with the app database.
4. **Keep the app database private.** It holds password hashes, session
   hashes, encrypted credentials and the audit trail. Use a dedicated
   PostgreSQL role and `sslmode=require` or stricter.
5. **Pin SSH host keys** on every tunnelled connection.
6. **Use scoped database accounts** per connection on the target side.
7. **Rate-limit `POST /login`** at the proxy.

The container runs as a non-root user, exposes port 8080 and answers
`GET /healthz` for liveness checks. Migrations run automatically at start.
Back up the app database before upgrading; roll back only after reconciling
any `running` history rows, since older binaries do not understand them.

## Screens

| Screen | Purpose |
|---|---|
| **Sign in** | Local email/password login; unauthenticated requests redirect here |
| **Dashboard** | KPIs, 24 h query volume, slow queries, recent connections, pending requests, activity feed |
| **Connections** | Create/edit/test connections (admin and DBA); one connection reaches every database its credentials can see |
| **SQL Editor** | Schema tree, editor with highlighting and formatting, Run / Stop, LIMIT selector, masked result grid, export, saved queries and history |
| **Database Explorer** | Object tree with columns, constraints, indexes and your effective permissions on each table |
| **Query History** | Day-grouped timeline with risk badges, blocked-query callouts and replay |
| **Audit Logs** | Severity-coded event list with category filters and a detail panel (admin, DBA, auditor) |
| **Security Center** | Posture score, threat feed, per-environment policy editors and masking rules (editing is admin only) |
| **Users & Roles** | Create users, assign roles, enable or disable accounts (admin only) |
| **Approval Requests** | Review one-time query approvals and PAM access windows; requesters see their own, approvers and auditors see all |

## Project structure

```
cmd/server            entrypoint
internal/auth         sessions, CSRF, login, password change
internal/audit        audit log service + screens
internal/approvals    approval workflow
internal/config       configuration loading
internal/connections  connection CRUD + credential encryption
internal/connectors   DBConnector interface, Postgres and MySQL drivers, SSH tunnel
internal/dashboard    dashboard data
internal/db           pool + embedded migration runner
internal/pam          just-in-time access windows
internal/policies     policy engine, SQL analysis, masking, security center
internal/query        execution pipeline, history, editor/explorer handlers
internal/security     AES-GCM, token helpers
internal/seed         roles, default policies, initial admin account
internal/settings     runtime-tunable settings
internal/users        user management
internal/web          router, template engine, templates, static assets
migrations            SQL migrations (embedded)
docker                Dockerfile for the app image
```

`make build` produces a single self-contained binary at `bin/securedb`.

## Tests

```bash
make test        # unit tests
make check       # go vet + tests
```

Unit tests cover both SQL dialects, role capabilities, TLS configuration,
schema checks, source-aware masking, connection authorization and proxy IP
handling. Database integration tests additionally cover approval binding,
concurrency and expiry, PAM role boundaries, native read-only execution,
metadata and export authorization, and audit or policy outages. CI runs
`gofmt`, `go vet`, `govulncheck`, the Go tests against PostgreSQL 17 and
MySQL 8.4, and the JavaScript tests. To run the integration tests locally
against disposable instances (the PostgreSQL user needs permission to create
and drop test schemas):

```bash
SECUREDB_TEST_DATABASE_URL='postgres://postgres:test@localhost:5432/securedb_test?sslmode=disable' \
SECUREDB_TEST_MYSQL_DSN='root:test@tcp(localhost:3306)/securedb_test' \
go test -race ./...
```

## Roadmap

- Login rate limiting and account lockout
- Per-connection permissions (`connection_permissions` table already migrated)
- Microsoft SQL Server connector (`github.com/microsoft/go-mssqldb` behind the existing stub)
- Azure AD / Office 365 SSO (OIDC) on the existing session layer
- `EXPLAIN` visualisation (toolbar placeholder exists)
- CodeMirror editor (the textarea is intentionally isolated in `editor.html`)
- Vault / AWS Secrets Manager resolution for `secrets_reference`
- Shared cancel registry so **Stop** works across instances

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report security issues privately per [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Dian Nedelchev
