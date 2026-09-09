# DigitalOcean provisioning and immutable delivery

This runbook provisions and delivers the supported production topology: one
DigitalOcean Ubuntu 24.04 LTS Droplet, one local SQLite database, one Docker
Compose application service, and private HTTPS through Tailscale Serve. It does
not provide multi-host availability. Do not put the SQLite database on NFS,
Spaces, a shared volume, or another network filesystem.

Nothing in this repository runs `tofu apply`, creates a release tag, publishes
an image, changes GHCR visibility, or enrolls a Tailscale node. Those are
deliberate operator actions.

## Resources, charges, and boundaries

`infrastructure/digitalocean` creates exactly:

- one basic Droplet from `ubuntu-24-04-x64`, with DigitalOcean monitoring and
  weekly Droplet backups enabled;
- one stateful DigitalOcean Cloud Firewall;
- one project and one tag used to attach the firewall before the Droplet is
  created.

The default size is `s-1vcpu-2gb`; the variable allowlist also permits only two
nearby basic sizes. Check current regional availability and
[DigitalOcean pricing](https://www.digitalocean.com/pricing/droplets) before
every apply. Compute, the backup plan, taxes, outbound transfer beyond the
included allowance, optional remote state storage, and independently managed
off-host application backups can all cost money. Cloud Firewalls, projects,
tags, and basic monitoring may currently have no separate charge, but current
DigitalOcean pricing is authoritative.

DigitalOcean Droplet backups are provider-level, crash-consistent recovery
material. They do **not** replace the verified application backups, off-host
copies, retention, and restore drills in
[the VPS runbook](vps-deployment.md#3-live-backups-and-retention).

The Cloud Firewall has no public rules for TCP 80, TCP 443, or TCP 8000.
Bootstrap SSH is allowed only from operator-supplied IPv4 `/24` through `/32`
networks; prefer a current `/32`. Outbound access is limited to DNS, NTP,
HTTP/HTTPS for supported package and registry access, Tailscale STUN, and ICMP.
IPv6 is disabled on the Droplet.

Direct Tailscale UDP is disabled by default. Tailscale remains functional over
its encrypted DERP relays through outbound TCP 443, although relayed traffic can
be slower. `tailscale_direct_peer_cidrs` may add inbound UDP 41641 and outbound
UDP only for stable, explicit `/24`-`/32` peer networks. Never use
`0.0.0.0/0`; roaming peers are better left on DERP than represented by a broad,
brittle allow rule.

## Prerequisites

Before planning, obtain:

1. OpenTofu 1.12.6 and Git.
2. A DigitalOcean account with billing deliberately enabled and an API token
   authorized only for the resources this root manages.
3. At least one existing DigitalOcean SSH **public** key ID or fingerprint.
   OpenTofu never accepts or reads a private key.
4. The operator's current public IPv4 address expressed as a `/32`, plus a
   tested DigitalOcean recovery-console path.
5. A tailnet administrator who can approve the node, configure grants, and
   enable HTTPS certificates.
6. Permission to read `ghcr.io/udaykyama/googleproject`, or a plan to make the
   package public manually after reviewing the exposure tradeoff.
7. An encrypted, access-controlled state-storage decision and an independent
   encrypted off-host destination for finalized application backups.

### Protect OpenTofu state first

OpenTofu state is sensitive even though this configuration intentionally keeps
tokens, SSH private keys, Tailscale keys, GHCR credentials, `SECRET_KEY`, and
application data out of it. State records infrastructure identifiers, public
addresses, and rendered non-secret cloud-init.

No backend is committed because backend credentials and the operator's state
system are account-specific. For individual evaluation, use local state only
on an encrypted workstation and keep an encrypted backup. For team operation,
choose a remote encrypted backend with versioning, access logging, and tested
concurrency/locking before the first apply. Supply backend credentials through
the backend's environment variables or an ignored local backend configuration,
never a committed `.tf` or `.tfvars` file. Do not copy state into tickets or
CI artifacts, and never commit `*.tfstate` or plan files.

OpenTofu requires the backend type in a `.tf` block. If the selected service is
S3-compatible, copy `backend.tf.example` to the ignored
`backend_override.tf`, keep access keys in the backend's standard environment
variables, and pass account-specific non-secret settings through an ignored
`-backend-config` file. Do not assume an S3-compatible service implements
locking correctly; test concurrent-plan protection. For a different backend,
write the corresponding ignored block from that backend's official
documentation. Review `git status --ignored` before continuing.

## Initialize and review a plan

Work from a reviewed release checkout:

```bash
cd infrastructure/digitalocean
cp terraform.tfvars.example terraform.tfvars
chmod 0600 terraform.tfvars
```

Replace every placeholder. Use an existing numeric SSH key ID or its
colon-delimited fingerprint. Set `operator_ssh_cidrs` to the public source
address from which the first SSH connection will actually originate. Keep
`tailscale_direct_peer_cidrs = []` unless fixed peer networks justify direct
UDP. Keep `disable_public_ssh = false` for bootstrap and leave
`confirm_billable_resources = false` while reviewing inputs.

Export the DigitalOcean token only in the operator shell:

```bash
read -rsp 'DigitalOcean API token: ' DIGITALOCEAN_TOKEN
export DIGITALOCEAN_TOKEN
printf '\n'
```

For a side-effect-free syntax check with no backend:

```bash
tofu fmt -check -recursive ..
tofu init -backend=false -input=false -lockfile=readonly
tofu validate
```

Before a real plan, initialize the protected backend selected above. Plain
`tofu init` uses local state when no `backend_override.tf` exists. Do not
proceed with that default unless encrypted local state is the explicit
decision. A configured remote backend should be initialized with its ignored
configuration, for example:

```bash
cp backend.tf.example backend_override.tf
tofu init -reconfigure -backend-config=/secure/path/backend.hcl
```

The referenced file must not contain long-lived credentials; use the backend's
environment variables for those. Omit these two commands for an explicitly
chosen encrypted local-state workflow.

After the backend is ready, set `confirm_billable_resources = true` and create
a saved plan:

```bash
tofu plan -out=inboxready.tfplan
tofu show inboxready.tfplan
```

The saved plan is sensitive and ignored by Git. Confirm it contains one
Droplet, one firewall, one project, and one tag; weekly backups and monitoring
are enabled; the image is Ubuntu 24.04 LTS; SSH sources are exactly the intended
CIDRs; and no inbound application ports exist. Check the provider-reported size
and region against current pricing. If anything differs, discard the plan and
fix the inputs rather than applying interactively.

`tofu apply inboxready.tfplan` is the first billable action. Run it only after
that review. This repository and its CI never run it.

After apply, record the non-secret outputs:

```bash
tofu output
tofu output -raw droplet_public_ipv4
```

The Droplet has `prevent_destroy = true`. This protects against an ordinary
accidental destroy but does not protect data from account compromise, manual
control-panel deletion, disk failure, or an operator deliberately removing the
lifecycle rule.

## Verify bootstrap without losing SSH

Cloud-init installs only Ubuntu-supported packages and non-secret host
prerequisites: Docker Engine, Docker Compose v2, unattended security upgrades,
the dedicated `inboxready-deploy` account, and application/config/data/backup
directories. It does not run `curl | sh`, clone the application, pull an image,
or receive any secret.

The DigitalOcean-injected root public keys are copied to the dedicated account.
Password SSH is disabled, but root public-key SSH remains available during
bootstrap. The deployment account has no sudo policy. It is in the `docker`
group, which is effectively root-equivalent Docker daemon access; keep it
dedicated to reviewed delivery commands.

Use the source address allowed by `operator_ssh_cidrs`:

```bash
ssh root@DROPLET_PUBLIC_IPV4
cloud-init status --wait
cloud-init status --long
docker compose version
exit

ssh inboxready-deploy@DROPLET_PUBLIC_IPV4
id
docker version
exit
```

If cloud-init or the copied key fails, retain the working root session and use
the recovery console. Do not narrow SSH, disable root key access, or enable UFW
until a second tested access path exists.

## Enroll Tailscale explicitly

Do not place a reusable or ephemeral Tailscale auth key in OpenTofu variables,
cloud-init, shell history, or state. Reopen a root SSH session from the
operator workstation and follow Tailscale's current Ubuntu 24.04
package-repository instructions. The explicit equivalent below downloads the
repository key and one-line source definition without executing a remote
script:

```bash
ssh root@DROPLET_PUBLIC_IPV4
curl -fsSLo /tmp/tailscale-archive-keyring.gpg \
  https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg
curl -fsSLo /tmp/tailscale.list \
  https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list
grep -Fx \
  'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu noble main' \
  /tmp/tailscale.list
sudo install -o root -g root -m 0644 /tmp/tailscale-archive-keyring.gpg \
  /usr/share/keyrings/tailscale-archive-keyring.gpg
sudo install -o root -g root -m 0644 /tmp/tailscale.list \
  /etc/apt/sources.list.d/tailscale.list
rm -f /tmp/tailscale-archive-keyring.gpg /tmp/tailscale.list
sudo apt-get update
sudo apt-get install --no-install-recommends tailscale
```

Re-check these URLs against Tailscale's current official documentation before
running them. Do not use the convenience `curl | sh` installer.

Then start an interactive, operator-authorized enrollment:

```bash
sudo tailscale up
tailscale status
tailscale ip -4
tailscale netcheck
```

A tailnet administrator must approve the device and grant only the intended
team access. Keep this root session open while testing the recovery paths
below. Private HTTPS is configured after the application is deployed.

Never use Tailscale Funnel for this service. Before removing the public SSH
CIDR, open a second SSH session over the Tailscale address, verify the intended
account and administrative recovery path, and confirm the DigitalOcean console
works. Then set `disable_public_ssh = true` and
`operator_ssh_cidrs = []`, review the OpenTofu plan that removes only the TCP
22 rule, and apply it **from a separate operator-workstation shell** while the
known-good root and Tailscale sessions remain open. Keep
`disable_public_ssh = false` and an explicit `/32` if public SSH is an
intentional recovery path. Close the original root session only after the
Tailscale SSH path and recovery console still work.

## Publish and select an immutable GHCR image

Run every Git and GitHub command in this section from the reviewed operator
workstation checkout, never from the production host.

`.github/workflows/release-image.yml` is the only image release path. It runs
for an existing `vMAJOR.MINOR.PATCH` tag, either when that tag is pushed or by a
controlled manual dispatch. The tag must be annotated, cryptographically signed
and verified by GitHub, point to a commit on the repository's default branch,
and match `project.version` in `pyproject.toml`. A manual run must select the
default branch as the workflow ref and provide the existing release tag as its
input.

Before the first release, add a repository tag ruleset for `v*` that limits tag
creation to release maintainers and blocks tag updates and deletion. This is a
GitHub repository setting and is intentionally not changed by this PR.

Create a release only after the commit and version change are reviewed:

```bash
git tag -s vMAJOR.MINOR.PATCH -m 'Release vMAJOR.MINOR.PATCH' COMMIT_SHA
git push origin vMAJOR.MINOR.PATCH
```

The verification job has only `contents: read`; only its dependent publish job
adds `packages: write` to `GITHUB_TOKEN`. It builds the existing production
Dockerfile for `linux/amd64`, uses Buildx caching, adds OCI labels, and
publishes BuildKit provenance and SBOM attestations. It creates only the
semantic tag and a `sha-FULL_COMMIT_SHA` tag, refuses to overwrite either, and
never deploys the VPS. The workflow summary records the only deployment form
operators should use:

```text
ghcr.io/udaykyama/googleproject@sha256:FULL_64_CHARACTER_DIGEST
```

Tags are discovery labels; the digest is the approval boundary. Record the
digest **and full release commit** in the change ticket and compare both with
the workflow summary before deployment.

GHCR package visibility is an operator decision this repository does not
change. A public package can be pulled anonymously. If the package remains
private, create a dedicated machine-user token with only `read:packages` (and
only any additional repository access GitHub requires for a private source
repository), authorize it for organization SSO if applicable, and log in
as the dedicated deployment account without putting it in the application
environment. Use the Tailscale IP/name after private access is verified; use
the public bootstrap address only while its restricted SSH rule intentionally
remains:

```bash
ssh inboxready-deploy@TAILSCALE_IP_OR_BOOTSTRAP_IPV4
read -rsp 'GHCR pull token: ' GHCR_TOKEN
printf '%s' "$GHCR_TOKEN" |
  docker login ghcr.io --username MACHINE_USER --password-stdin
unset GHCR_TOKEN
exit
```

Docker stores the pull credential in the deployment user's Docker
configuration. Restrict that file to the account, rotate the token, and revoke
it when the host is retired. Never use a personal token with write/delete
package scopes on the VPS.

## Configure and deploy the approved digest

Clone the same reviewed release that produced the image:

```bash
ssh root@TAILSCALE_IP_OR_BOOTSTRAP_IPV4
sudo -H -u inboxready-deploy \
  git clone https://github.com/Udaykyama/googleproject.git /opt/inboxready
cd /opt/inboxready
RELEASE_TAG=vMAJOR.MINOR.PATCH
RELEASE_COMMIT=FULL_40_CHARACTER_COMMIT_FROM_WORKFLOW
sudo -H -u inboxready-deploy git fetch --force origin \
  "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"
test "$(
  sudo -H -u inboxready-deploy git cat-file -t "refs/tags/$RELEASE_TAG"
)" = tag
test "$(
  sudo -H -u inboxready-deploy \
    git rev-parse "refs/tags/$RELEASE_TAG^{commit}"
)" = "$RELEASE_COMMIT"
sudo -H -u inboxready-deploy git checkout --detach "$RELEASE_COMMIT"
test "$(sudo -H -u inboxready-deploy git rev-parse HEAD)" = "$RELEASE_COMMIT"
```

Create the root-owned application environment without printing the generated
secret:

```bash
sudo install -o root -g inboxready-deploy -m 0640 /dev/null \
  /etc/inboxready/app.env
sudo sh -c 'umask 0027; printf "SECRET_KEY=%s\n" "$(openssl rand -hex 32)" > /etc/inboxready/app.env'
sudoedit /etc/inboxready/app.env
```

Keep the generated `SECRET_KEY` line stable and add:

```dotenv
APP_IMAGE=ghcr.io/udaykyama/googleproject@sha256:FULL_64_CHARACTER_DIGEST
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

Store a recovery copy of `SECRET_KEY` in the operator's existing encrypted
secret manager. Do not put it in GitHub Actions, OpenTofu, user-data, a
`.tfvars` file, or a ticket. Rotation invalidates current browser sessions and
CSRF tokens.

Validate, pull, and start exactly the approved digest:

```bash
exit
ssh inboxready-deploy@TAILSCALE_IP_OR_BOOTSTRAP_IPV4
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
ss -ltn | grep '127.0.0.1:8000'
```

The production command pulls with `--policy always`, verifies Docker recorded
the requested repository digest, and starts with `--no-build --pull never`.
`compose.yaml` has no production build section. A tag, another registry, a
non-SHA256 reference, a missing environment file, or missing required setting
fails before deployment. The wrapper clears exported Compose/application
variables before reading the root-owned env file; never `source` that file into
an operator shell.

Install and start the existing backup and operational timers only after the
first verified manual backup, following
[the VPS runbook](vps-deployment.md#3-live-backups-and-retention). Verify both
local and tailnet readiness, the two CLIs, structured logs, log rotation,
timer status, disk headroom, and backup integrity exactly as documented there.
Arrange encrypted off-host copying of finalized `moderation-*.sqlite3` files
and complete a restore drill before considering the service recoverable.
Open or return to a root/recovery session over the verified access path for
systemd installation and any `ss -ltnp` inspection; `inboxready-deploy`
intentionally has no sudo grant. From that root or Tailscale-admin session,
enable the private HTTPS proxy and verify it targets only loopback:

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8000
tailscale serve status
```

Never use `tailscale funnel`. Verify `/readyz` and `/healthz` from an
authorized tailnet client after Serve is active.

## Roll back by prior digest

Record every deployed digest and retain at least one previously tested image.
Confirm the prior image supports the current SQLite schema. Rollback changes
only `APP_IMAGE`; never change or replace the bind mounts. Edit the protected
environment from the retained root/recovery path, then run Docker as the
deployment account so it uses that account's restricted GHCR credential:

```bash
ssh root@TAILSCALE_IP_OR_BOOTSTRAP_IPV4
cd /opt/inboxready
cp --preserve=mode,ownership \
  /etc/inboxready/app.env /etc/inboxready/app.env.pre-rollback
editor /etc/inboxready/app.env
# Set APP_IMAGE to the previously approved ghcr.io/...@sha256: digest.
sudo -H -u inboxready-deploy \
  deploy/production-compose --env-file /etc/inboxready/app.env deploy
curl -fsS http://127.0.0.1:8000/readyz
sudo -H -u inboxready-deploy \
  docker compose --project-name inboxready \
    --file /opt/inboxready/compose.yaml \
    --env-file /etc/inboxready/app.env exec -T app \
  fake-review-detector verify \
    --database /var/lib/inboxready/moderation.sqlite3 \
    --integrity --require-anchor
```

If validation fails, restore the prior environment file and run the same
digest-only deploy command. Do not rebuild during an incident and call it a
rollback.

## Destroy and data-loss warning

Destroying the Droplet destroys its local SQLite database and local backups.
Provider backups are not a substitute for a verified off-host restore. Before
retirement, stop writes, create and verify a final application backup, copy it
to the encrypted off-host destination, perform or confirm a restore drill, and
record the retained `SECRET_KEY` and image digest under the operator's data
retention policy.

The committed `prevent_destroy` rule intentionally blocks `tofu destroy`.
Removing it must be a separately reviewed code change made only after the data
sign-off above. Then review `tofu plan -destroy` before any destructive action.
Destroying cloud resources does not automatically sanitize copied state,
plans, GHCR credentials, off-host backups, or secret-manager entries; retire
each according to policy and preserve any required audit evidence.
