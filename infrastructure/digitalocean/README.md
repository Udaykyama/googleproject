# DigitalOcean OpenTofu root

This root module models one protected Ubuntu LTS Droplet, one Cloud Firewall,
one project, and one tag. It creates no resources until an operator supplies
inputs and explicitly runs `tofu apply`.

Use the complete [DigitalOcean provisioning and delivery runbook](../../docs/digitalocean-deployment.md).
OpenTofu state is sensitive, is intentionally not committed, and must be
protected before the first billable apply.
