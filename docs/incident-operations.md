# Incident operations

This runbook is for the supported deployment: one Linux VPS, the `app` service
from `compose.yaml`, multiple Gunicorn workers, SQLite on local persistent disk,
loopback-only publication, and private access through Tailscale Serve. Tailnet
membership is the identity boundary; the application has no login.

Do not paste `.env`, SQLite files, backups, uploaded content, review bodies,
session/CSRF values, or full container inspection output into an incident
ticket. Do not run `tailscale funnel`, delete SQLite sidecars, re-anchor an
unverified audit chain, or use broad Docker cleanup during diagnosis.

## First response

Work from the reviewed checkout and record UTC times:

```bash
cd /opt/inboxready
date -u
docker compose ps --all
curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
sudo systemctl status \
  inboxready-backup.service \
  inboxready-operational-check.service \
  --no-pager
docker compose logs --since 30m --tail 500 --no-color app
```

Run the same read-only check used by the timer. It emits one JSON document and
returns nonzero if any condition fails:

```bash
docker compose run --rm --no-deps -T app \
  fake-review-detector operational-check \
    --readiness-url http://app:8000/readyz \
    --data-dir /var/lib/inboxready \
    --backup-dir /var/backups/inboxready \
    --min-free-bytes 1073741824 \
    --min-free-percent 10 \
    --max-backup-age 129600 \
    --readiness-timeout 5 \
    --backup-timeout 30
```

Use its stable `code` fields to choose the section below. Declare an incident
immediately if the live database or newest backup fails integrity, no verified
backup exists, free space is still falling, the app cannot be restored without
changing data, or private access appears to have become public.

## Readiness failure

`/healthz` returning 200 while `/readyz` returns 503 isolates the failure to
SQLite or its transactional audit anchor. Both failing suggests the process or
container is unavailable.

```bash
docker compose ps --all
APP_CONTAINER=$(docker compose ps --all -q app)
if test -n "$APP_CONTAINER"; then
  docker inspect --format '{{json .State}}' "$APP_CONTAINER"
else
  echo "No app container has been created."
fi
docker compose logs --since 15m --tail 500 --no-color app
sudo journalctl -u inboxready-operational-check.service \
  --since '-1 hour' --no-pager
```

Application events identify the normalized route and a safe exception type,
not exception text or storage paths. Correlate a reported request using its
bounded ID:

```bash
docker compose logs --since 1h --tail 1000 --no-color app \
  | grep --fixed-string '"request_id":"REPORTED_REQUEST_ID"'
```

Do not repeatedly restart a storage failure. Check disk and backup integrity
first. If both are healthy and the failure was transient, make one controlled
restart and re-run readiness:

```bash
docker compose restart app
docker compose up -d --wait app
curl -fsS http://127.0.0.1:8000/readyz
```

## Container crash loop

Inspect the state and recent lifecycle output without dumping the container
environment, which contains `SECRET_KEY`:

```bash
docker compose ps --all
APP_CONTAINER=$(docker compose ps --all -q app)
if test -n "$APP_CONTAINER"; then
  docker inspect --format \
    'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}' \
    "$APP_CONTAINER"
else
  echo "No app container has been created."
fi
docker compose logs --since 30m --tail 500 --no-color app
docker image inspect inboxready:local --format '{{.Id}} {{.Created}}'
```

If restarts obscure the first error, stop the service once, preserve evidence,
and run it attached:

```bash
docker compose stop app
docker compose up app
```

Use `Ctrl-C` after capturing the failure, then either roll back to a known image
or restore a verified database as described below. Do not remove the persistent
directories or use `docker compose down --volumes`.

## Low disk

Confirm which local filesystem is constrained and whether usage is increasing:

```bash
df -h /srv/inboxready/data /srv/inboxready/backups
df -i /srv/inboxready/data /srv/inboxready/backups
sudo du -x -h --max-depth=1 /srv/inboxready
docker system df
```

Do not delete `moderation.sqlite3`, `-wal`, or `-shm`, partial files during an
active backup, or finalized backups that have not been copied and verified
elsewhere. Docker application logs are already bounded to five 10 MiB files.
The safe responses are to add disk capacity, move independently verified
finalized backups to the operator's encrypted off-host store, or deliberately
lower backup retention after confirming the recovery objective.

After restoring headroom, run one verified backup and the operational check:

```bash
sudo systemctl start inboxready-backup.service
sudo journalctl -u inboxready-backup.service -n 50 --no-pager
sudo systemctl start inboxready-operational-check.service
sudo journalctl -u inboxready-operational-check.service -n 20 -o cat --no-pager
```

## Stale or invalid backup

Inspect the scheduler before creating another snapshot:

```bash
systemctl list-timers inboxready-backup.timer
sudo systemctl status inboxready-backup.service --no-pager
sudo journalctl -u inboxready-backup.service --since '-2 days' --no-pager
```

Select only a finalized timestamped file and verify it through the existing
SQLite/audit API:

```bash
BACKUP_NAME=$(sudo find /srv/inboxready/backups -maxdepth 1 -type f \
  -name 'moderation-*.sqlite3' -printf '%f\n' | LC_ALL=C sort | tail -n 1)
test -n "$BACKUP_NAME"
docker compose run --rm --no-deps -T app \
  fake-review-detector verify \
    --database "/var/backups/inboxready/$BACKUP_NAME" \
    --integrity --require-anchor
```

For a stale but valid backup, fix the timer or disk issue and run the backup
service. For an invalid newest backup, preserve it as evidence, verify older
finalized snapshots newest-first, and verify the live database before taking a
new snapshot. Never make an invalid file appear healthy by renaming it or
rewriting its anchor.

## SQLite busy or corruption symptoms

A `StorageBusyError` can be transient; repeated occurrences indicate a long
writer, exhausted I/O, or another stack using the same database. Confirm only
the intended Compose project is running and inspect its processes:

```bash
docker compose ps --all
docker compose top app
docker ps --filter label=com.docker.compose.project=inboxready
```

Then run the established verifier against the live database:

```bash
docker compose exec -T app \
  fake-review-detector verify \
    --database /var/lib/inboxready/moderation.sqlite3 \
    --integrity --require-anchor
```

If contention persists, stop new moderation work and escalate before restarting
the sole app service. If integrity or the audit anchor fails, stop the app and
restore a known verified backup using the deployment runbook. Do not run ad hoc
SQLite repair commands, copy a live WAL database with filesystem tools, delete
sidecars, or combine a database with WAL/SHM files from another point in time.

## Tailscale access failure

First separate backend health from private network access:

```bash
curl -fsS http://127.0.0.1:8000/readyz
sudo ss -ltnp | grep '127.0.0.1:8000'
tailscale status
tailscale serve status
tailscale netcheck
```

If loopback readiness works, have a tailnet administrator verify node approval,
HTTPS enablement, grants/ACLs, and the intended team membership. Confirm Serve
still targets `http://127.0.0.1:8000` and that Funnel is not enabled. Preserve a
working SSH/recovery session while changing network policy; follow the lockout
precautions in [the deployment runbook](vps-deployment.md).

## Safe rollback to a known image

Rollback changes the image, never the data mounts. Use an operator-recorded,
previously tested immutable image tag or digest and confirm it supports the
current SQLite schema. Record the current image ID first:

```bash
cd /opt/inboxready
CURRENT_IMAGE=$(docker image inspect inboxready:local --format '{{.Id}}')
KNOWN_IMAGE=inboxready:release-KNOWN_GOOD
docker image inspect "$KNOWN_IMAGE" --format '{{.Id}} {{.Created}}'

docker compose stop app
docker image tag "$KNOWN_IMAGE" inboxready:local
docker compose up -d --no-build --wait app
curl -fsS http://127.0.0.1:8000/readyz
docker compose exec -T app \
  fake-review-detector verify \
    --database /var/lib/inboxready/moderation.sqlite3 \
    --integrity --require-anchor
```

If rollback validation fails, stop the app. The recorded ID can be retagged to
return to the prior image:

```bash
docker compose stop app
docker image tag "$CURRENT_IMAGE" inboxready:local
docker compose up -d --no-build --wait app
```

Do not rebuild during an incident and call it a rollback; a rebuild can resolve
different dependencies or base layers. Do not roll back across an incompatible
storage change without the corresponding tested data procedure.

## Verified restore drill

At the recovery interval chosen by the operator, restore a finalized backup on
a disposable host using the complete fail-fast block in
[Verified restore drill](vps-deployment.md#5-verified-restore-drill). The drill
must prove all of the following without reading or exporting review content:

1. The selected backup passes `verify --integrity --require-anchor` before use.
2. The app writer is stopped before database and matching sidecars are moved.
3. The restored service reaches `/readyz`.
4. The restored live database passes the same verifier.
5. Expected audit record counts and timestamps are recorded as metadata.

Keep the source backup unchanged and retain the pre-restore database set until
the drill is signed off. A successful `docker compose up` alone is not a restore
test.

## Evidence collection without content leakage

Create a mode-0700 working directory and collect bounded operational metadata:

```bash
umask 077
INCIDENT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/inboxready-incident.XXXXXX")
date -u > "$INCIDENT_DIR/time.txt"
git rev-parse HEAD > "$INCIDENT_DIR/revision.txt"
docker compose version > "$INCIDENT_DIR/compose-version.txt"
docker compose config --images > "$INCIDENT_DIR/images.txt"
docker compose ps --all > "$INCIDENT_DIR/compose-ps.txt"
docker compose logs --since 2h --tail 2000 --no-color app \
  > "$INCIDENT_DIR/app.log"
sudo journalctl \
  -u inboxready-backup.service \
  -u inboxready-operational-check.service \
  --since '-2 hours' --no-pager \
  > "$INCIDENT_DIR/systemd.log"
tailscale status > "$INCIDENT_DIR/tailscale-status.txt"
tailscale serve status > "$INCIDENT_DIR/tailscale-serve.txt"
```

Application logs are designed not to contain bodies, raw queries, cookies,
tokens, or storage paths, but still treat the bundle as restricted operational
data. Review it before transfer. Never collect `.env`, full `docker inspect`
output, database/backup files, HTML responses, core dumps, or uploaded content
unless an authorized evidence owner establishes a separate encrypted process.

## Escalation and follow-up

Escalate host/disk and Docker failures to the VPS operator, tailnet/Serve policy
failures to the tailnet administrator, and SQLite/audit integrity or application
regressions to the application owner. The operator decides the paging vendor,
recipients, severity mapping, and secure evidence channel.

After recovery:

1. Record the UTC timeline, impact, request IDs, image IDs, and stable check
   cause codes.
2. Complete a verified restore drill if backup recoverability was involved.
3. Fix the root cause with a reviewed change and regression test; do not leave
   an incident-only host edit undocumented.
4. Revisit disk and backup-age thresholds, off-host retention, alert routing,
   and immutable image retention.
5. Rotate `SECRET_KEY` only if evidence shows it was exposed; rotation
   invalidates every browser session and CSRF token.
