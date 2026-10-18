# SecureDB Web Client

[![CI](https://github.com/diannedelchev/securedb/actions/workflows/ci.yml/badge.svg)](https://github.com/diannedelchev/securedb/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/diannedelchev/securedb)](https://goreportcard.com/report/github.com/diannedelchev/securedb)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A secure, browser-based database client for **PostgreSQL**, **MySQL/MariaDB** and
**Microsoft SQL Server** (stub). Query remote databases from a desktop browser or
iPad — no local client installs — with security controls: encrypted
credentials, RBAC, per-environment query policies, approval workflows, data
masking and a full audit trail.

**Stack:** Go · Fiber v3 · PostgreSQL · server-side rendered HTML · HTMX · custom CSS.
**UI:** dark-first enterprise design system (IBM Plex Sans/Mono, deep navy palette,
compact data density) implemented from the SecureDB Claude Design project —
Login, Dashboard, Connections + wizard, SQL Editor, Database Explorer, Query
History, Audit Logs, Security Center, Users & Roles, and Approval Requests all
follow the design screens, with responsive breakpoints for iPad widths.

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
            → PostgresConnector / MySQLConnector / MSSQLConnector (stub)
               → Target databases
```

Database credentials are AES-256-GCM encrypted in the app database, decrypted
just-in-time inside the connector layer, and **never sent to the browser**.

## Quick start

### Fully containerized (zero config)

```bash
git clone https://github.com/diannedelchev/securedb.git && cd securedb
make up          # docker compose up --build -d
```

Open **http://localhost:8080** and sign in with the seeded admin account
(**admin@securedb.local / admin1234!** — dev only). The stack brings up the
app and its PostgreSQL database; add your own database connections from the
**Connections** page.

### Local development (app on host, database in Docker)

Use Go 1.26.9 or newer. CI checks dependencies with `govulncheck`.

```bash
make config      # creates config.yaml with a generated encryption key
# Set seed.admin.password in config.yaml before continuing.
make dev         # starts app-db, then runs the app
```

Open **http://localhost:8080** (or whatever `app.addr` you set).

Run `make` with no arguments to list all targets (`test`, `vet`, `logs`,
`reset`, …).

## Configuration

Configuration is layered — later sources win:

1. **Built-in defaults**
2. **`config.yaml`** (path via `CONFIG_FILE`, default `./config.yaml`) — see
   `config.example.yaml`. It points the app at an **existing PostgreSQL server**
   (`database.host/port/name/user/password` or a full `database.url`), sets the
   listen address, encryption key, session lifetimes and the seed account.
   Create it with `make config`.
3. **Environment variables** — `APP_ADDR`, `APP_ENV`, `DATABASE_URL`,
   `APP_ENCRYPTION_KEY`, `COOKIE_SECURE`, `TRUST_PROXY_IP`, `SESSION_TTL`,
   `SESSION_IDLE_TTL`, `SEED_ADMIN_*`. The docker-compose
   stack uses these so a fresh clone runs with zero setup; for real
   deployments mount a `config.yaml` instead (see the comments in
   `docker-compose.yml`).
4. **`app_settings` table** in the application database — runtime-tunable
   settings (session TTL / idle TTL). Seeded from config on first boot, edited
   afterwards on the admin **Settings** page; changes apply without a restart
   and the database value wins.

> ⚠️ The `APP_ENCRYPTION_KEY` and admin password in `docker-compose.yml` are
> **public and for local evaluation only**. Generate your own key
> (`openssl rand -hex 32` or `make key`) for anything else — all encrypted
> credentials become unreadable if the key changes, and anyone can decrypt
> them if it stays the public one.

### Initial account

On first boot against an empty database, seeding creates roles, per-environment
security policies, masking rules and a **single admin login** from
`seed.admin` in `config.yaml`:

```yaml
seed:
  admin:
    email: admin@securedb.local
    password: "change-me-now"   # required on first boot; choose your own password
    name: Administrator
```

Create further users on **Users & Roles**, and connect your own databases on
**Connections** (PostgreSQL or MySQL/MariaDB). The docker-compose stack uses
`SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` instead — dev-only values, see the
comments there.

Set `seed.admin.password` or `SEED_ADMIN_PASSWORD` before the first boot.
An empty password stops initial account creation; passwords are never logged.
Existing installations with users do not require a seed password on restart.
If an earlier version generated a password in the server log, change that
account's password and remove the exposed credential from retained logs.

### Try the guardrails

Once you have added a connection, open the SQL editor and try:

```sql
-- masking: columns matching card/iban/egn patterns come back masked
-- (emails and phones do not)
SELECT * FROM customers;

-- blocked for non-admins (no WHERE)
DELETE FROM customers;

-- blocked keyword
DROP TABLE payments;

-- on a connection labelled "production", a write from a non-privileged
-- account creates an approval request instead of executing
UPDATE customers SET first_name = 'X' WHERE id = 1;
```

Approve it as an admin/DBA on **Approval Requests** (the detail pane shows
the SQL, an automated risk analysis and a timeline), then run it from the
requester's account with the one-time **Run approved query** button.

## Screens

| Screen | What it does |
|---|---|
| **Sign in** | Split-screen login at `/login` — the entry point for anonymous visitors (any unauthenticated request redirects here; signed-in users land on the Dashboard) |
| **Dashboard** | KPI cards, 24h query-volume histogram, slow queries, recent connections, environment status, pending access requests, activity timeline |
| **Connections** | Card grid with env/read-only/tag chips, last-used, test/edit/connect; wizard-style create/edit form with selectable auth methods. **One connection covers every database on the server** — it stores a default database, and the editor/explorer can switch to any other database the credentials can reach (PostgreSQL via `pg_database`, MySQL via schemas) |
| **SQL Editor** | Full-bleed IDE: schema tree, tabs, Run ⌘⏎ / Explain / Stop, LIMIT selector (100 / 500 default / Unlimited) + READ-ONLY chip, line-numbered editor, result grid with masking badges, Copy rows, saved queries & history rail; production banner with approval-reason input |
| **Database Explorer** | Three-pane: filterable object tree → tabbed Columns/Constraints/Indexes grid → inspector with object stats and your effective permissions |
| **Query History** | Day-grouped timeline with risk badges, blocked-query callouts, expandable execution detail, replay & copy |
| **Audit Logs** | Severity-coded event list with category pills, click-through detail panel (statement, actor, origin) — auditors/DBAs/admins only |
| **Security Center** | Posture score computed from live policy config, threat timeline, blocked-queries chart, risk indicators, per-environment policy editors, masking rules |
| **Users & Roles** | Role badges, permission summaries, per-user manage modal (roles + enable/disable), admin only |
| **Approval Requests** | Master-detail review of both request types: one-time query approvals (SQL, automated risk checks, risk meter) and **PAM access windows** — just-in-time, time-bound write grants (15m–8h) requested via the "Request access window" button, approved/revoked by Admins/DBAs (four-eyes). While a window is active, the holder's production writes run without per-query approval (tagged `JIT WINDOW`); hard guardrails and auditing still apply |

## Modules

| Module | Where | Notes |
|---|---|---|
| Authentication | `internal/auth` | Local login, server-side sessions (SHA-256 hashed tokens), CSRF, idle + absolute timeout. `Authenticate` is the single seam for adding Azure AD/O365 SSO. |
| Users & roles | `internal/users` | admin, dba, developer, qa, analyst, auditor |
| Connections | `internal/connections` | CRUD, test, encrypted passwords, `secrets_reference` placeholder for Vault/ASM |
| Connectors | `internal/connectors` | `DBConnector` interface; Postgres + MySQL implemented, MSSQL stub |
| Query pipeline | `internal/query` | role + parsed policy checks → block/approve → durable execution intent → execute (timeout + row cap, cancellable) → mask → durable outcome |
| Policy engine | `internal/policies` | per-environment max rows/timeout/blocked keywords/write rules; fails closed on unknown statements; risk scoring |
| Data masking | `internal/policies/masking.go` | source-column rules: card/pan, iban, password/secret, national_id/egn; aliases retain their source rules, and uncertain result provenance is fully redacted |
| Approvals | `internal/approvals` | pending/approved/rejected/expired, four-eyes (no self-approval), one-time execution, 24 h expiry |
| Audit | `internal/audit` | every security-sensitive action with user, IP, user agent, query text, severity |
| Dashboard | `internal/dashboard` | live stats and feeds for the operational grid |

## Security model

- Passwords: bcrypt. DB credentials: AES-256-GCM with `app.encryption_key`
  from `config.yaml`; never rendered to any template.
- Sessions: opaque 256-bit cookie token, hash stored server-side; `HttpOnly`,
  `SameSite=Lax`, `Secure` in production; idle + absolute expiry.
- CSRF: per-session token verified on every state-changing request (form field
  or `X-CSRF-Token`, sent automatically by HTMX).
- PostgreSQL and MySQL reads execute in database-enforced read-only transactions,
  including reads on otherwise writable connections. Explicit read-only connections
  reject writes for every role. Query sessions pin PostgreSQL standard-conforming
  strings and MySQL's standard strict SQL mode so parsing and execution agree.
- SQL is parsed with libpg_query (embedded WebAssembly, no CGo required) for
  PostgreSQL and TiDB's MySQL parser. Invalid or unsupported syntax fails closed;
  non-admin UPDATE/DELETE statements need their own WHERE, including inside CTEs.
- Analysts can read; auditors cannot query targets. QA can write outside production;
  developers, DBAs and admins can write subject to policy. Approval/PAM never adds
  capabilities missing from a user's roles.
- Enabling SSL requires encryption and certificate/hostname verification for both
  connectors. Install private CA certificates in the server/container trust store
  (or configure PostgreSQL's supported root certificate setting); self-signed or
  untrusted endpoints no longer silently connect.
- App-database access is fully parameterised (pgx); user SQL only ever reaches
  *target* databases through the connector layer.
- Optional **SSH tunnel** per connection (bastion/jump host): password or
  private-key auth, credentials AES-256-GCM encrypted at rest, optional host-key
  fingerprint pinning (mismatches are rejected; empty pin accepts any key — dev
  only). One SSH session per database connection, torn down with it.
- PAM (Privileged Access Management): just-in-time access windows are
  four-eyes approved, auto-expire, are revocable, and never bypass hard
  guardrails (blocked keywords, WHERE rules, read-only connections). Grant
  lifecycle events (`grant_requested/approved/rejected/revoked`) are audited.
- Multi-database switching validates database names as plain identifiers before
  they touch a DSN; query history and approvals record the target database, and
  an approval is atomically consumed for the exact requester, connection, database
  and SQL it was reviewed for. Expired/used approvals and approvals predating a
  connection edit cannot execute.
- With `allowed_schemas` configured, SQL table references must be explicitly
  schema-qualified and match exactly; the same policy guards explorer endpoints.
  Routines, casts, implicit search paths and unsupported access paths are rejected
  under this restriction. CTE references without schema qualification are also
  conservatively rejected. Views and target-side routines still require carefully
  scoped database credentials: application checks do not replace database grants.
- Masking uses parsed direct source columns, not aliases. Expressions, subqueries,
  CTEs, mixed wildcards and other uncertain projections are fully redacted when
  masking is enabled. Token suffixes cannot exempt a sensitive source column.
  For arbitrary analytics with reliable column-level access control, use database
  views/permissions with restricted credentials. Masking is not protection against
  inference through query predicates or target-side objects that rename data.
- Export controls apply to the supported CSV/JSON download flow, with a server
  policy check and durable audit before download. Already displayed data remains
  copyable. Export attribution uses the originating history record, even after the
  editor text or selected connection changes.
- Missing/unreadable policy or masking configuration blocks execution. Query history
  and audit intent commit before target SQL starts; completion updates both atomically
  with bounded retries. A remaining `running` record means the outcome is unconfirmed
  (including after a process crash). Inspect the target and logs using the history ID
  before retrying writes; the application never automatically replays target SQL.
- Audit logs record IP, user agent and submitted SQL. Avoid embedding credentials in
  SQL literals: query history and audit logs retain the submitted statement.

### Policy defaults

- Row limit chosen per run in the editor: **100**, **500** (default) or **Unlimited**; the
  policy's max rows (**500**) is only the fallback when no selection is sent. Timeout **30 s**
  (editable per environment in Security Center)
- Blocked keywords for non-admins: `DROP, TRUNCATE, ALTER, CREATE, GRANT, REVOKE`
- `DELETE`/`UPDATE` without `WHERE`: blocked for non-admins
- Multi-statement requests: blocked for non-admins
- Production writes: require Admin/DBA approval (24 h expiry, executes once)

## Project structure

```
cmd/server            entrypoint
internal/auth         sessions, CSRF, login handlers
internal/audit        audit log service + screens
internal/approvals    approval workflow
internal/config       env configuration
internal/connections  connection CRUD + credential encryption
internal/connectors   DBConnector interface + drivers
internal/dashboard    dashboard data
internal/db           pool + embedded migration runner
internal/policies     policy engine, masking, security center
internal/query        execution pipeline, history, editor/explorer handlers
internal/security     AES-GCM, token helpers
internal/seed         roles, default policies, initial admin account
internal/users        user management
internal/web          router, template engine, templates, static assets
migrations            SQL migrations (embedded)
docker                Dockerfile for the app image
```

Templates, static assets and migrations are embedded — `make build` produces a
single self-contained binary at `bin/securedb`.

## Tests

```bash
make test
```

Unit tests cover both SQL dialects, role capabilities, TLS configuration, schema
checks and source-aware masking. Database integration tests additionally cover
approval binding/concurrency/expiry, PAM role boundaries, native read-only execution,
metadata/export authorization and audit/policy outages. CI runs these against
isolated PostgreSQL 17 and MySQL 8.4 services. To run them locally against disposable
instances (the PostgreSQL test user needs permission to create/drop test schemas):

```bash
SECUREDB_TEST_DATABASE_URL='postgres://postgres:test@localhost:5432/securedb_test?sslmode=disable' \
SECUREDB_TEST_MYSQL_DSN='root:test@tcp(localhost:3306)/securedb_test' \
go test -race ./...
```

Migration `0008_execution_audit.sql` adds the durable running state. Deploy migrations
with the new binary. Before rolling back to older code, reconcile all running rows;
older binaries do not provide the new execution/audit guarantees.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report security issues privately per [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Dian Nedelchev

## Roadmap (post-MVP)

- Microsoft SQL Server connector (`github.com/microsoft/go-mssqldb` behind the existing stub)
- Azure AD / Office365 SSO (OIDC) on the existing session layer
- CodeMirror editor (textarea is intentionally isolated in `editor.html`)
- Result export + `EXPLAIN` visualisation (toolbar placeholders exist)
- Vault / AWS Secrets Manager resolution for `secrets_reference`
- Per-connection permissions (`connection_permissions` table already migrated)
- Redis-backed sessions for multi-instance deployments (compose profile `cache`)
