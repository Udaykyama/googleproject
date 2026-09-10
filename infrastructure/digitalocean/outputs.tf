output "droplet_id" {
  description = "DigitalOcean Droplet ID."
  value       = digitalocean_droplet.app.id
}

output "droplet_public_ipv4" {
  description = "Bootstrap-only public IPv4 address. Application ports remain blocked by the Cloud Firewall."
  value       = digitalocean_droplet.app.ipv4_address
}

output "deployment_user" {
  description = "Dedicated non-sudo application delivery account."
  value       = local.deployment_user
}

output "firewall_id" {
  description = "Cloud Firewall protecting the tagged Droplet."
  value       = digitalocean_firewall.app.id
}

output "project_id" {
  description = "DigitalOcean project containing the Droplet."
  value       = digitalocean_project.app.id
}

output "estimated_droplet_price" {
  description = "Provider-reported Droplet compute price after apply; backup charges and taxes are additional."
  value = {
    hourly  = digitalocean_droplet.app.price_hourly
    monthly = digitalocean_droplet.app.price_monthly
  }
}

output "provisioned_resources" {
  description = "Resources this root module creates. It does not create Tailscale, GHCR, DNS, volumes, or off-host backup storage."
  value = {
    billable_droplets = 1
    cloud_firewalls   = 1
    projects          = 1
    tags              = 1
    droplet_backups   = "weekly-enabled"
    monitoring        = "enabled"
  }
}
