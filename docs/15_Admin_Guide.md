# Administrator Guide

## Start and stop

Copy `.env.example` to `.env`, set a unique `SECRET_KEY`, then run `docker compose up --build`. Browse to `http://localhost:8080`; Swagger is at `http://localhost:8000/docs`. Stop with Ctrl+C or `docker compose down`. `docker compose down -v` removes the demo database volume and all demo data.

## Accounts and roles

The seed creates 12 fictional accounts named `user1@demo.bank` through `user12@demo.bank`. Every account uses `DemoPass!234`. Roles cover platform admin, analyst, manager, approver, security architect, auditor, remediation owner, and executive. Change the shared demo password policy only for newly created accounts; do not use these accounts outside the isolated demo.

## Configuration

Settings are environment variables: `DATABASE_URL`, `SECRET_KEY`, `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, and `MFA_REQUIRED`. Enabling MFA enforcement requires privileged users to enroll TOTP before they can log in. Keep secrets out of source control. `ANTHROPIC_API_KEY` is optional; an empty value selects the fallback assistant.

## Synthetic data

`python backend/scripts/generate_synthetic_data.py` rewrites `backend/data/synthetic/` with deterministic fixtures. The Docker build runs this generator. The seed loader only acts when the asset table is empty. To reseed after a schema/data change, remove the named database volume and rebuild.

## TLS profile

With OpenSSL installed, run `./infra/tls/generate-local-cert.ps1`, then `docker compose --profile tls up --build`. Visit `https://localhost:8443`. The certificate is self-signed and intended only for local transport testing. Delete local certificate files after the demo if they are no longer needed.

## Backup and restore

Use `backend/scripts/backup.sh <file.dump>` with `DATABASE_URL` set to a reachable PostgreSQL connection. Restore to a disposable database with `backend/scripts/restore.sh <file.dump>`. Restore uses `--clean`, so the target schema is replaced. For Docker, connect to the `db` service from inside the Compose network or use a host-mapped development URL.

## Troubleshooting

- **API unhealthy:** inspect `docker compose logs backend db`; confirm PostgreSQL is healthy and migration completed.
- **Frontend cannot load API:** use the mapped UI origin and inspect browser network errors; allowed origins are local 5173/8080 and TLS 8443.
- **Login fails:** confirm seed finished and use an enabled seeded account; five failures cause a 15-minute lock.
- **Empty graph:** run Attack Paths → Recalculate paths; graph rows require exposed entries and crown-jewel targets connected in the inventory.
- **Claude unavailable:** unset the key or check the provider; fallback answers remain available.
- **Reset demo:** `docker compose down -v` then `docker compose up --build`.
