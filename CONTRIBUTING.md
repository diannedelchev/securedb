# Contributing

Thanks for your interest in contributing to SecureDB Web Client! This document
covers the development workflow. For bugs and feature requests, open an issue
first so the change can be discussed before you invest time in a PR.

## Development setup

Requirements: Go (version in `go.mod`), Docker, and `make`.

```bash
git clone https://github.com/diannedelchev/securedb.git
cd securedb

# Either: fully containerized stack (app + database, seeded admin account)
make up          # http://localhost:8080 — admin@securedb.local / admin1234!

# Or: app on the host, database in Docker (better for iterating)
make config      # creates config.yaml with a generated encryption key
make dev
```

## Before submitting a PR

```bash
make check       # go vet + go test
gofmt -w .       # CI rejects unformatted code
```

- Add tests for changes to the policy engine, masking, or any
  security-sensitive path (`internal/policies`, `internal/auth`,
  `internal/security`, `internal/query`).
- Keep handlers thin; business rules live in the module services under
  `internal/`.
- Database schema changes go in a new, sequentially numbered file in
  `migrations/` (embedded, applied at boot — see `internal/db`).
- Templates and static assets are embedded; no extra build step.

## Security

Never commit secrets (`config.yaml` is git-ignored for this reason). Report
vulnerabilities privately — see [SECURITY.md](SECURITY.md).
