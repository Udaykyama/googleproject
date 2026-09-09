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

- the VPS address, an initial account with SSH/sudo access, and a separate
  `inboxready-deploy` account with no sudo policy;
- a tailnet administrator to authorize the node, enable HTTPS, and grant only
  the intended team access;
- a stable random application secret of at least 32 characters;
- distinct persistent local paths for application data and backups;
- an independently administered off-host backup destination and retention
  policy;
- an approved immutable
  `ghcr.io/udaykyama/googleproject@sha256:<64-hex-digest>` image reference.

Do not commit `/etc/inboxready/app.env`, the generated secret, registry
credentials, SQLite files, uploaded mail, review data, or backups. The
repository ignores standard local names, but the operator remains responsible
for the host and off-host copies.

## 1. Prepare the host

For the reviewed DigitalOcean/OpenTofu path, follow the complete
[DigitalOcean provisioning and immutable delivery runbook](digitalocean-deployment.md).
For another provider, install a supported Docker Engine and Docker Compose v2
from a trusted distro or vendor repository, then create the same fixed
deployment boundary. From the operator workstation, connect as the initial
sudo-capable account:

```bash
ssh INITIAL_ADMIN@VPS_ADDRESS
if getent passwd inboxready-deploy >/dev/null ||
   getent group inboxready-deploy >/dev/null; then
  echo "inboxready-deploy must be a new account and group dedicated to this app" >&2
  exit 1
fi
sudo groupadd inboxready-deploy
sudo useradd --create-home --gid inboxready-deploy --shell /bin/bash \
  inboxready-deploy
sudo passwd --lock inboxready-deploy
sudo usermod --append --groups docker inboxready-deploy
sudo chmod 0750 /home/inboxready-deploy
test -s "$HOME/.ssh/authorized_keys"
sudo install -d -o inboxready-deploy -g inboxready-deploy -m 0700 \
  /home/inboxready-deploy/.ssh
sudo install -o inboxready-deploy -g inboxready-deploy -m 0600 \
  "$HOME/.ssh/authorized_keys" \
  /home/inboxready-deploy/.ssh/authorized_keys
sudo install -d -o inboxready-deploy -g inboxready-deploy -m 0750 \
  /opt/inboxready
```

The Docker group is root-equivalent; this account is least-privilege only in
the sense that it is dedicated, password-locked, and has no sudo policy. Test a
second SSH login as `inboxready-deploy` before closing the bootstrap session.
From the initial administrator session, clone and detach at the full release
commit recorded by the image workflow, and verify the signed release tag
targets that same commit:

```bash
RELEASE_TAG=vMAJOR.MINOR.PATCH
RELEASE_COMMIT=FULL_40_CHARACTER_COMMIT_FROM_WORKFLOW
sudo -H -u inboxready-deploy \
  git clone https://github.com/Udaykyama/googleproject.git /opt/inboxready
sudo -H -u inboxready-deploy git -C /opt/inboxready fetch --force origin \
  "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"
test "$(
  sudo -H -u inboxready-deploy \
    git -C /opt/inboxready rev-parse "refs/tags/$RELEASE_TAG^{commit}"
)" = "$RELEASE_COMMIT"
sudo -H -u inboxready-deploy \
  git -C /opt/inboxready checkout --detach "$RELEASE_COMMIT"
test "$(
  sudo -H -u inboxready-deploy git -C /opt/inboxready rev-parse HEAD
)" = "$RELEASE_COMMIT"
```

Create the bind-mount directories for the image's fixed non-root UID. Keep data
and backups on a local filesystem, not NFS, SMB, or another network mount:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/inboxready/data /srv/inboxready/backups
sudo install -d -o root -g inboxready-deploy -m 0750 /etc/inboxready
sudo install -o root -g inboxready-deploy -m 0640 /dev/null \
  /etc/inboxready/app.env
sudo sh -c 'umask 0027; printf "SECRET_KEY=%s\n" "$(openssl rand -hex 32)" > /etc/inboxready/app.env'
```

Edit `/etc/inboxready/app.env`, preserve the generated `SECRET_KEY`, and add:

```dotenv
APP_IMAGE=ghcr.io/udaykyama/googleproject@sha256:<approved-64-hex-digest>
APP_DATA_DIR=/srv/inboxready/data
BACKUP_DIR=/srv/inboxready/backups
APP_PORT=8000
GUNICORN_WORKERS=2
GUNICORN_THREADS=4
LIVE_DNS=0
LOG_FORMAT=json
LOG_LEVEL=INFO
LOG_CLIENT_ADDRESS=0
```

Keep this secret stable across restarts and deployments. Rotating it invalidates
existing browser sessions and CSRF tokens. Store a recovery copy in the
operator's encrypted secret manager. Compose refuses to render when any
required image, path, or secret is blank, and the application rejects a short
SQLite mode secret.

If GHCR remains private, first complete the least-privilege pull login in
[Publish and select an immutable GHCR image](digitalocean-deployment.md#publish-and-select-an-immutable-ghcr-image)
as the deployment account. Then validate, pull, and start the approved digest:

```bash
exit
ssh inboxready-deploy@VPS_ADDRESS
cd /opt/inboxready
unset \
  APP_IMAGE APP_DATA_DIR BACKUP_DIR SECRET_KEY APP_PORT \
  GUNICORN_WORKERS GUNICORN_THREADS LIVE_DNS LOG_FORMAT LOG_LEVEL \
  LOG_CLIENT_ADDRESS COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES \
  COMPOSE_ENV_FILES COMPOSE_DISABLE_ENV_FILE COMPOSE_PATH_SEPARATOR
deploy/production-compose --env-file /etc/inboxready/app.env config
deploy/production-compose --env-file /etc/inboxready/app.env deploy
docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env ps
curl -fsS http://127.0.0.1:8000/readyz
```

The production command rejects tags and other repositories, verifies the
pulled repository digest, and starts with `--no-build --pull never`.
It clears exported Compose/application variables so they cannot outrank the
protected env file; never `source` that file. `compose.yaml` contains no build
path. For local-only build and development, set `APP_IMAGE=inboxready:local` in
a mode-0600 local env file and opt into the separate override:

```bash
docker compose --project-name inboxready-local \
  -f compose.yaml -f compose.local.yaml \
  --env-file .env build --pull
docker compose --project-name inboxready-local \
  -f compose.yaml -f compose.local.yaml \
  --env-file .env up -d --wait
```

The final image contains an installed wheel and packaged templates, CSS, demos,
and sample data; it does not run from the source checkout. It runs as UID/GID
10001 with a read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, a bounded PID count, a writable temporary tmpfs, rotated
container logs, privacy-safe structured request events, and graceful Gunicorn
shutdown. Gunicorn's raw access log is disabled because it includes unbounded
request targets and query strings. The two original CLIs remain available:

```bash
docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env exec app inboxready --help
docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env exec app fake-review-detector --help
```

Confirm Docker published only a loopback socket:

```bash
ss -ltn | grep '127.0.0.1:8000'
```

Do not add a public `0.0.0.0` port mapping, and do not open port 8000 in the
provider firewall.

## 2. Join the tailnet and enable private HTTPS

Leave the non-sudo deployment shell and reconnect as the initial
sudo-capable administrator before host networking or systemd work:

```bash
exit
ssh INITIAL_ADMIN@VPS_ADDRESS
```

Follow Tailscale's current Linux package-repository instructions. On Ubuntu,
add its signed APT repository and explicitly install the `tailscale` package;
do not use a `curl | sh` convenience installer. Enroll interactively so an auth
key is not stored in OpenTofu state, cloud-init, or shell history:

```bash
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
join the VPS to Tailscale, open a **second** SSH session for the initial
sudo-capable administrator over its Tailscale address, verify sudo access
there, and confirm the provider's recovery console works. Only then adjust the
provider firewall and host firewall.

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
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env exec -T app \
  fake-review-detector backup \
  --database /var/lib/inboxready/moderation.sqlite3 \
  --output-dir /var/backups/inboxready \
  --keep 14
```

Return to the initial sudo-capable administrator session before installing the
supplied daily systemd timer. If the checkout is not `/opt/inboxready`, update
every checkout and Compose path in both service units first:

```bash
sudo install -m 0644 \
  /opt/inboxready/deploy/systemd/inboxready-backup.service \
  /etc/systemd/system/inboxready-backup.service
sudo install -m 0644 \
  /opt/inboxready/deploy/systemd/inboxready-backup.timer \
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

## 4. Structured logs and operational checks

The Compose deployment selects one-line JSON application logs. Each completed
request includes a UTC timestamp, severity, stable event name, bounded request
ID, method, normalized Flask route and endpoint, status, duration, and process
ID. It never records the raw URL or query string, submitted mail/review bodies,
form/session/CSRF values, or exception messages. Unexpected failures record an
exception type and bounded module/function locations without source paths or
local values. A dedicated Gunicorn logger also replaces parser errors with a
fixed `gunicorn.invalid_request` event rather than echoing malformed request
lines or headers.

A caller-supplied `X-Request-ID` is reused only when it is 1-64 characters from
the restricted ASCII token alphabet; all other values are replaced with a
server-generated ID. The selected ID is returned in the response header. Use it
to correlate a report with a request event:

```bash
curl -i -H 'X-Request-ID: operator-check-20260908' \
  http://127.0.0.1:8000/readyz
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env \
  logs --since 15m --tail 500 --no-color app \
  | grep --fixed-string '"request_id":"operator-check-20260908"'
```

Client address logging is off by default because IP addresses are personal
data and are not the identity boundary. If an operator explicitly sets
`LOG_CLIENT_ADDRESS=1`, the logger accepts only the single normalized IP in
`remote_addr` after the declared `TRUSTED_PROXY_HOPS` processing. It never logs
the raw `X-Forwarded-For` chain. Do not use the logged address as a substitute
for tailnet membership or policy.

Docker's `json-file` storage is bounded to five 10 MiB files. Inspect the
current service, rotation configuration, application logs, and system logs
without reading the database or uploads:

```bash
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env ps
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file /opt/inboxready/compose.yaml \
  --env-file /etc/inboxready/app.env \
  logs --since 1h --tail 500 --no-color app
APP_CONTAINER=$(
  sudo -H -u inboxready-deploy \
    docker compose --project-name inboxready \
    --file /opt/inboxready/compose.yaml \
    --env-file /etc/inboxready/app.env ps -q app
)
sudo -H -u inboxready-deploy \
  docker inspect --format '{{json .HostConfig.LogConfig}}' "$APP_CONTAINER"
sudo journalctl \
  -u inboxready-backup.service \
  -u inboxready-operational-check.service \
  --since today --no-pager
```

The dependency-free `operational-check` command emits one JSON document and
exits zero only when all four conditions hold:

- the app's local `/readyz` response is ready before its timeout;
- the persistent data filesystem has at least 1 GiB **and** 10% free;
- the latest finalized backup is no more than 36 hours old; and
- that backup passes the same full SQLite and audit-anchor verification used
  before backup publication.

It reports stable cause codes such as `readiness_timeout`, `disk_space_low`,
`backup_stale`, and `backup_integrity_failed`, never paths or response bodies.
It does not delete or repair anything. The supplied service runs the check in a
temporary container so it can still report a stopped or unreachable app while
using the production image and read-only check logic. Its systemd path check is
an assertion, so a missing deployment checkout fails and reaches `OnFailure`
rather than silently skipping monitoring.

After the first manual verified backup exists, install the six-hour timer:

```bash
sudo install -m 0644 \
  /opt/inboxready/deploy/systemd/inboxready-operational-check.service \
  /etc/systemd/system/inboxready-operational-check.service
sudo install -m 0644 \
  /opt/inboxready/deploy/systemd/inboxready-operational-check.timer \
  /etc/systemd/system/inboxready-operational-check.timer
sudo systemctl daemon-reload
sudo systemctl start inboxready-operational-check.service
sudo journalctl -u inboxready-operational-check.service -n 20 -o cat --no-pager
sudo systemctl enable --now inboxready-operational-check.timer
systemctl list-timers inboxready-operational-check.timer
```

The timer runs at most four times per day, starts 15 minutes after boot, and
adds up to 15 minutes of jitter. Adjust the free-space and backup-age arguments
in the installed service to match the provisioned disk and recovery objective;
keep both nonzero in production and run `systemctl daemon-reload` after edits.

Paging delivery remains an operator choice. Once an operator-owned executable
at `/usr/local/sbin/inboxready-notify` accepts a failed unit name and has been
tested with its credentials stored outside this repository, the supplied
vendor-neutral template can be installed:

```bash
sudo install -m 0644 \
  /opt/inboxready/deploy/systemd/inboxready-alert@.service.example \
  /etc/systemd/system/inboxready-alert@.service
sudo systemctl edit inboxready-operational-check.service
```

Add this drop-in, then reload systemd:

```ini
[Unit]
OnFailure=inboxready-alert@%p.service
```

```bash
sudo systemctl daemon-reload
sudo systemctl start inboxready-alert@inboxready-operational-check.service
```

The repository deliberately does not choose a pager, webhook, credentials, or
delivery policy. The six-hour cadence bounds repeated notifications, but the
operator notifier should also deduplicate and route according to local policy.

## 5. Verified restore drill

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

APP_ENV_FILE=/etc/inboxready/app.env
APP_COMPOSE_FILE=/opt/inboxready/compose.yaml
unset \
  APP_IMAGE APP_DATA_DIR BACKUP_DIR SECRET_KEY APP_PORT \
  GUNICORN_WORKERS GUNICORN_THREADS LIVE_DNS LOG_FORMAT LOG_LEVEL \
  LOG_CLIENT_ADDRESS COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES \
  COMPOSE_ENV_FILES COMPOSE_DISABLE_ENV_FILE COMPOSE_PATH_SEPARATOR
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
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file "$APP_COMPOSE_FILE" --env-file "$APP_ENV_FILE" exec -T app \
  fake-review-detector verify \
  --database "/var/backups/inboxready/$BACKUP_NAME" \
  --integrity --require-anchor

sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file "$APP_COMPOSE_FILE" --env-file "$APP_ENV_FILE" stop app
running=$(
  sudo -H -u inboxready-deploy \
    docker compose --project-name inboxready \
    --file "$APP_COMPOSE_FILE" --env-file "$APP_ENV_FILE" \
    ps --status running --services app
)
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

sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file "$APP_COMPOSE_FILE" --env-file "$APP_ENV_FILE" \
  up -d --no-build --pull never --wait app
curl -fsS http://127.0.0.1:8000/readyz
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
  --file "$APP_COMPOSE_FILE" --env-file "$APP_ENV_FILE" exec -T app \
  fake-review-detector verify \
  --database /var/lib/inboxready/moderation.sqlite3 \
  --integrity --require-anchor
```

Keep the `.pre-restore-*` files until application behavior and expected record
counts are confirmed. If validation fails, stop the app and move that preserved
set back as a unit; do not combine a database file with WAL/SHM files from a
different snapshot.

For diagnosis and response procedures covering readiness, crash loops, disk,
backups, SQLite, Tailscale, rollback, evidence collection, and escalation, use
the [incident operations runbook](incident-operations.md).

## Operating boundaries

- `STORAGE=sqlite` does not import, overwrite, or delete legacy JSON queue/audit
  files. Migration requires a separately designed and tested procedure.
- `/healthz` proves the process responds. `/readyz` also checks that SQLite and
  its audit anchor are accessible; use readiness for deployment decisions.
- The operational check is local and timer-driven. There is intentionally no
  public metrics endpoint and no per-worker in-memory counter surface.
- `LIVE_DNS=0` is the default. If enabled, every authorized tailnet member with
  access can ask the service to query arbitrary domains. Query budgets,
  deadlines, bounded worker admission, and shared SQLite token buckets reduce
  abuse but do not make public exposure safe.
- Uploaded messages and review batches are processed in memory, but SQLite
  contains production moderation history. Treat the data and every backup as
  sensitive.
- This is one-host durability, not high availability. Host loss takes the
  service down, and host-disk loss takes local data and local backups with it.
