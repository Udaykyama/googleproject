# Private single-VPS deployment

This runbook deploys the web UI to one Linux VPS with Docker Compose and makes
it reachable only through Tailscale Serve. Tailscale terminates HTTPS and
controls who can reach the service; the application intentionally has no login
system.

## Scope and operator inputs

This topology is deliberately narrow:

- one Linux host, one Compose app service, and multiple Gunicorn workers;
- one SQLite database on a persistent **local** filesystem;
- a loopback-only host port proxied by private Tailscale Serve, never Funnel;
- local timestamped backups with bounded retention.

It is not multi-host failover or disaster recovery. The operator must provide:

- the VPS address and an account with SSH/sudo access;
- a tailnet administrator to authorize the node, enable HTTPS, and grant only
  the intended team access;
- a stable random application secret of at least 32 characters;
- distinct persistent local paths for application data and backups;
- an independently administered off-host backup destination and retention
  policy.

Do not commit `.env`, the generated secret, SQLite files, uploaded mail, review
data, or backups. The repository ignores the standard local names, but the
operator remains responsible for the host and off-host copies.

## 1. Prepare the host

Install a supported Docker Engine and the Docker Compose plugin from Docker's
official repository. Clone this repository at the reviewed release commit into
`/opt/inboxready`.

Create the bind-mount directories for the image's fixed non-root UID. Keep data
and backups on a local filesystem, not NFS, SMB, or another network mount:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/inboxready/data /srv/inboxready/backups
cd /opt/inboxready
install -m 0600 .env.example .env
openssl rand -hex 32
```

Edit `.env`, paste the generated value into `SECRET_KEY`, and set:

```dotenv
APP_DATA_DIR=/srv/inboxready/data
BACKUP_DIR=/srv/inboxready/backups
SECRET_KEY=<paste-the-generated-64-hex-character-value>
APP_PORT=8000
GUNICORN_WORKERS=2
GUNICORN_THREADS=4
LIVE_DNS=0
```

Keep this secret stable across restarts and deployments. Rotating it invalidates
existing browser sessions and CSRF tokens. Compose refuses to render when any
required path or secret is blank, and the application rejects a short SQLite
mode secret.

Build, validate, and start:

```bash
docker compose config --quiet
docker compose build --pull
docker compose up -d --wait
docker compose ps
curl -fsS http://127.0.0.1:8000/readyz
```

The final image contains an installed wheel and packaged templates, CSS, demos,
and sample data; it does not run from the source checkout. It runs as UID/GID
10001 with a read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, a bounded PID count, a writable temporary tmpfs, rotated
container logs, and graceful Gunicorn shutdown. The two original CLIs remain
available:

```bash
docker compose exec app inboxready --help
docker compose exec app fake-review-detector --help
```

Confirm Docker published only a loopback socket:

```bash
sudo ss -ltnp | grep '127.0.0.1:8000'
```

Do not add a public `0.0.0.0` port mapping, and do not open port 8000 in the
provider firewall.

## 2. Join the tailnet and enable private HTTPS

Follow Tailscale's current Linux installation instructions. On Debian/Ubuntu,
the official bootstrap flow is:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale status
tailscale ip -4
```

A tailnet administrator may need to approve the node, enable HTTPS certificates,
and update grants/ACLs so only the team can reach it. Team membership and
tailnet policy are the identity boundary; moderator names in the UI are still
unverified attribution labels.

Proxy the loopback service with persistent Tailscale Serve HTTPS:

```bash
sudo tailscale serve --bg --https=443 http://127.0.0.1:8000
tailscale serve status
```

Use the `https://<node>.<tailnet>.ts.net` URL printed by that command. No public
domain or public certificate is required. Never run `tailscale funnel` for this
deployment: Funnel is public internet exposure, while Serve obeys tailnet
access controls and resumes after reboot when configured with `--bg`.

Compose sets `TRUSTED_PROXY_HOPS=1` for this exact one-proxy topology. Do not
place another proxy in the path without updating and reviewing that trust
boundary.

From an authorized tailnet client, verify:

```bash
curl -fsS https://<node>.<tailnet>.ts.net/readyz
curl -fsS https://<node>.<tailnet>.ts.net/healthz
```

From the VPS, verify the backend remains loopback-only with `ss`, and from a
non-tailnet network verify that the Serve URL and port 8000 are unreachable.

### Firewall and lockout caution

Do not remove public SSH access while it is your only working session. First
join the VPS to Tailscale, open a **second** SSH session over its Tailscale
address, verify sudo access there, and confirm the provider's recovery console
works. Only then adjust the provider firewall and host firewall.

For UFW, inspect existing rules before changing them:

```bash
sudo ufw status verbose
sudo ufw allow in on tailscale0
```

The intended end state denies unsolicited public inbound traffic and allows the
`tailscale0` interface. Preserve whatever temporary SSH rule is required until
the second-session and console tests pass. Do not blindly copy commands that
delete port 22: SSH ports, cloud firewalls, and recovery paths differ. Docker
published ports can interact unexpectedly with firewall tooling, which is why
the Compose loopback binding and the `ss` check are mandatory even when UFW is
enabled.

## 3. Live backups and retention

The backup command opens the live WAL database read-only and uses SQLite's
backup API. It writes a hidden partial file, runs SQLite integrity checking,
streams and verifies the hash-chained audit history against its transactional
anchor, syncs the file, and only then atomically publishes a mode-0600
timestamped backup. A failed copy or verification exits nonzero and never
publishes the partial file. Retention touches only names produced by this
mechanism.

Run a manual backup while the app is serving traffic:

```bash
docker compose exec -T app fake-review-detector backup \
  --database /var/lib/inboxready/moderation.sqlite3 \
  --output-dir /var/backups/inboxready \
  --keep 14
```

Install the supplied daily systemd timer (edit the working directory first if
the checkout is not `/opt/inboxready`):

```bash
sudo install -m 0644 deploy/systemd/inboxready-backup.service \
  /etc/systemd/system/inboxready-backup.service
sudo install -m 0644 deploy/systemd/inboxready-backup.timer \
  /etc/systemd/system/inboxready-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now inboxready-backup.timer
sudo systemctl start inboxready-backup.service
systemctl list-timers inboxready-backup.timer
sudo journalctl -u inboxready-backup.service --since today
```

The timer retains 14 local snapshots and catches a missed run after reboot.
Monitor failed units and disk usage. These backups are still on the same host:
copy only finalized `moderation-*.sqlite3` files to an encrypted,
access-controlled off-host destination, with separate retention and restore
tests. Choosing that destination is an operator decision; this repository does
not add a vendor integration.

## 4. Restore test and incident runbook

Test this procedure periodically on a disposable host. The automated test suite
also restores a produced backup into a fresh path and verifies its anchor and
record count.

Set `BACKUP` to the finalized file being restored, then run this as one
fail-fast shell block. It checks both SQLite structure and the audit chain
before stopping production, proves the writer stopped, preserves every active
database sidecar, refuses a stale staging file, and rechecks the restored live
database:

```bash
set -euo pipefail
cd /opt/inboxready

BACKUP_DIR=/srv/inboxready/backups
BACKUP=$BACKUP_DIR/moderation-YYYYMMDDTHHMMSS.ffffffZ.sqlite3
DATA=/srv/inboxready/data
BACKUP=$(sudo realpath -- "$BACKUP")
case "$BACKUP" in
  "$BACKUP_DIR"/moderation-*.sqlite3) ;;
  *) echo "backup must be a finalized file in $BACKUP_DIR" >&2; exit 1 ;;
esac
BACKUP_NAME=$(basename "$BACKUP")
RESTORE_ID=$(date -u +%Y%m%dT%H%M%SZ)

sudo test -f "$BACKUP"
docker compose exec -T app fake-review-detector verify \
  --database "/var/backups/inboxready/$BACKUP_NAME" \
  --integrity --require-anchor

docker compose stop app
running=$(docker compose ps --status running --services app)
test -z "$running"
sudo test ! -e "$DATA/moderation.sqlite3.restore"

for suffix in "" "-wal" "-shm"; do
  file="$DATA/moderation.sqlite3${suffix}"
  if sudo test -e "$file"; then
    sudo mv -- "$file" "$file.pre-restore-$RESTORE_ID"
  fi
  sudo test ! -e "$file"
done

sudo install -o 10001 -g 10001 -m 0600 -- "$BACKUP" \
  "$DATA/moderation.sqlite3.restore"
sudo mv -- "$DATA/moderation.sqlite3.restore" "$DATA/moderation.sqlite3"

docker compose up -d --wait app
curl -fsS http://127.0.0.1:8000/readyz
docker compose exec -T app fake-review-detector verify \
  --database /var/lib/inboxready/moderation.sqlite3 \
  --integrity --require-anchor
```

Keep the `.pre-restore-*` files until application behavior and expected record
counts are confirmed. If validation fails, stop the app and move that preserved
set back as a unit; do not combine a database file with WAL/SHM files from a
different snapshot.

## Operating boundaries

- `STORAGE=sqlite` does not import, overwrite, or delete legacy JSON queue/audit
  files. Migration requires a separately designed and tested procedure.
- `/healthz` proves the process responds. `/readyz` also checks that SQLite and
  its audit anchor are accessible; use readiness for deployment decisions.
- `LIVE_DNS=0` is the default. If enabled, every authorized tailnet member with
  access can ask the service to query arbitrary domains. Query budgets,
  deadlines, bounded worker admission, and shared SQLite token buckets reduce
  abuse but do not make public exposure safe.
- Uploaded messages and review batches are processed in memory, but SQLite
  contains production moderation history. Treat the data and every backup as
  sensitive.
- This is one-host durability, not high availability. Host loss takes the
  service down, and host-disk loss takes local data and local backups with it.
