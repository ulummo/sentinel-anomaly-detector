# Sentinel pilot deployment (Docker + Caddy)

This is a deployment template, not a live server. Use a dedicated Linux VM with a static public IP, a DNS A/AAAA record for your domain, Docker Engine + Compose plugin, and firewall rules allowing inbound TCP 80/443 only (plus SSH restricted to your admin IP). Do not expose port 8000.

## Configure

1. Copy `deploy/.env.example` to `.env` in the repository root (the source file is inside `deploy/`).
2. Set `SENTINEL_DOMAIN`, `ACME_EMAIL`, and a unique 64-character random `SENTINEL_BOOTSTRAP_TOKEN`. Keep `.env` private; it is gitignored.
3. Start: `docker compose up -d --build`.
4. Check: `docker compose ps`, open `https://$SENTINEL_DOMAIN/` for the Streamlit dashboard, and check `https://$SENTINEL_DOMAIN/health` for the API.
5. Bootstrap the first owner exactly once using `POST /v1/auth/bootstrap` with header `X-Sentinel-Bootstrap`. Use a unique 16+ character password. Then remove the bootstrap secret from the runtime environment and rotate/remove it from the deployment secret store.
6. Enroll devices from the Streamlit console. Device sensors must use the HTTPS URL.

## Backups and restore

Run `sh deploy/backup.sh` daily using cron/systemd timer. Copy encrypted backups off-host to a separate account/location; the local script retains 14 days only. Test restore monthly on a separate machine before relying on backups. Restrict backup directory permissions to the service administrator.

## Updates and rollback

Before each update, make and verify a backup. Then `git pull --ff-only && docker compose up -d --build`. Check `/health`, logs, login, event ingestion, and device heartbeat. Keep the previous image tag and backup available for rollback. Do not run automatic database migrations against production without a tested restore.

## Operational hardening still required

Configure provider-level firewall, encrypted block storage, unattended security updates, host monitoring/alerts, log rotation, external backup replication, secret manager, incident contact, data-retention policy and restore drills. SQLite is suitable only for a small single-instance pilot; use managed PostgreSQL before scaling horizontally. Have an independent security professional review the deployment before processing customer data.
