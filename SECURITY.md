# Security Policy

SecureDB is a security-sensitive application: it brokers access to databases
and stores encrypted credentials. Vulnerability reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report them privately via
[GitHub Security Advisories](https://github.com/diannedelchev/securedb/security/advisories/new).

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- Affected version/commit, if known

You can expect an acknowledgment within a few days. Once the issue is
confirmed and a fix is available, a coordinated disclosure will be arranged
with credit to the reporter (unless you prefer to remain anonymous).

## Scope notes

- The seeded admin password and the `APP_ENCRYPTION_KEY` shipped in
  `docker-compose.yml` are **intentionally public for local evaluation only**
  and are not vulnerabilities. Never use them for a real deployment —
  generate your own key (`openssl rand -hex 32`) and set a real password.
- Hardening expectations for a production deployment: HTTPS with
  `app.cookie_secure: true`, a unique `app.encryption_key`, a private
  application database, and individually managed user accounts.

## Supported versions

Security fixes are applied to the latest commit on `main`. There are no
versioned releases with long-term support yet.
