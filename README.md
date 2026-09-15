# SecureDB Web Client

A secure, browser-based database client for **PostgreSQL**, **MySQL/MariaDB** and
**Microsoft SQL Server** (stub). Query remote databases from a desktop browser or
iPad — no local client installs — with bank-grade guardrails: encrypted
credentials, RBAC, per-environment query policies, approval workflows, data
masking and a full audit trail.

**Stack:** Go · Fiber v3 · PostgreSQL · server-side rendered HTML · HTMX · custom CSS.
**UI:** dark-first enterprise design system (IBM Plex Sans/Mono, deep navy palette,
compact data density) implemented from the SecureDB Claude Design project —
Login, Dashboard, Connections + wizard, SQL Editor, Database Explorer, Query
History, Audit Logs, Security Center, Users & Roles, and Approval Requests all
follow the design screens, with responsive breakpoints for iPad widths.

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

### Fully containerized

```bash
make up          # docker compose up --build -d
```

Open **http://localhost:8080**.

### Local development (app on host, databases in Docker)

```bash
make config      # creates config.yaml with a generated encryption key
make dev         # starts app-db + sample targets, then runs the app
```

Open **http://localhost:8080** (or whatever `app.addr` you set).

Run `make` with no arguments to list all targets (`test`, `vet`, `logs`,
`reset`, …).

## Configuration

Configuration is layered — later sources win:

1. **Built-in defaults**
2. **`config.yaml`** (path via `CONFIG_FILE`, default `./config.yaml`) — see
   `config.example.yaml`. This is the single configuration file: it points the
   app at an **existing PostgreSQL server** (`database.host/port/name/user/password`
   or a full `database.url`), sets the listen address, encryption key, session
   lifetimes and the seed account. The docker-compose stack mounts the same file
   into the container. Create it with `make config`.
3. **`app_settings` table** in the application database — runtime-tunable
   settings (session TTL / idle TTL). Seeded from config on first boot, edited
   afterwards on the admin **Settings** page; changes apply without a restart
   and the database value wins.

### Initial account

On first boot against an empty database, seeding creates roles, per-environment
security policies, masking rules and a **single admin login** from
`seed.admin` in `config.yaml`:

```yaml
seed:
  admin:
    email: admin@securedb.local
    password: "change-me-now"   # empty = one-time password printed to the log
    name: Administrator
```

Create further users on **Users & Roles**. Setting `seed.demo_data: true` in
`config.yaml` provisions the demo users and sample connections below instead.

### Demo accounts (docker-compose demo stack)

| Role      | Email                    | Password    |
|-----------|--------------------------|-------------|
| Admin     | admin@securedb.local     | admin1234!  |
| DBA       | dba@securedb.local       | dba1234!    |
| Developer | dev@securedb.local       | dev1234!    |
| Auditor   | auditor@securedb.local   | audit1234!  |

Seeded connections point at the bundled sample targets:

- **Demo PostgreSQL** — `target-postgres/demodb` (schema `app`: customers,
  payments, api_credentials — includes card/iban/egn columns to demo masking)
- **Demo MySQL** — `target-mysql/demodb` (customers, orders)
- **Prod PostgreSQL (demo)** — same target labelled *production* so you can
  walk the approval flow

> When running the app on the host (`make dev`), the seeded hostnames
> `target-postgres` / `target-mysql` are Docker-internal. Either run fully
> containerized (`make up`), or edit the two connections to
> `localhost:5434` (PostgreSQL) and `localhost:3307` (MySQL).

### Try the guardrails

```sql
-- masking: cards, IBANs and EGNs come back masked (emails/phones do not)
SELECT * FROM app.customers;
SELECT * FROM app.payments;

-- blocked for non-admins (no WHERE)
DELETE FROM app.customers;

-- blocked keyword
DROP TABLE app.payments;

-- production write → creates an approval request
-- (run on "Prod PostgreSQL (demo)" as dev@)
UPDATE app.customers SET first_name = 'X' WHERE id = 1;
```

Approve it as `dba@securedb.local` on **Approval Requests** (the detail pane
shows the SQL, an automated risk analysis and a timeline), then run it from
the requester's account with the one-time **Run approved query** button.

## Screens

| Screen | What it does |
|---|---|
| **Public site** | Marketing homepage at `/` for anonymous visitors (signed-in users land on the Dashboard), plus `/features`, `/privacy` and `/terms` — served from the same binary in the same design system |
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
| Query pipeline | `internal/query` | policy check → block/approve → execute (timeout + row cap, cancellable) → mask → history + audit |
| Policy engine | `internal/policies` | per-environment max rows/timeout/blocked keywords/write rules; fails closed on unknown statements; risk scoring |
| Data masking | `internal/policies/masking.go` | column-pattern rules: card/pan, iban, password/secret, national_id/egn; email, phone and `*token*` columns are never masked |
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
- Read-only connections additionally set `default_transaction_read_only=on`
  (PostgreSQL) and refuse writes at the connector level (MySQL).
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
  an approval is only executable against the exact SQL **and database** it was
  reviewed for.
- Audit log records IP and user agent; secrets are never logged.

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
internal/seed         roles, demo users, sample connections
internal/users        user management
internal/web          router, template engine, templates, static assets
migrations            SQL migrations (embedded)
docker                Dockerfile + sample target DB seeds
```

Templates, static assets and migrations are embedded — `make build` produces a
single self-contained binary at `bin/securedb`.

## Tests

```bash
make test
```

Covers the policy engine (statement classification, comment/literal stripping,
blocked keywords, WHERE-less writes, read-only enforcement, production approval
gate, risk scoring) and the masking engine (strategies, column matching, NULL
passthrough).

## Roadmap (post-MVP)

- Microsoft SQL Server connector (`github.com/microsoft/go-mssqldb` behind the existing stub)
- Azure AD / Office365 SSO (OIDC) on the existing session layer
- CodeMirror editor (textarea is intentionally isolated in `editor.html`)
- Result export + `EXPLAIN` visualisation (toolbar placeholders exist)
- Vault / AWS Secrets Manager resolution for `secrets_reference`
- Per-connection permissions (`connection_permissions` table already migrated)
- Redis-backed sessions for multi-instance deployments (compose profile `cache`)
