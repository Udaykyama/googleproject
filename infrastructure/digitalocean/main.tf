provider "digitalocean" {}

locals {
  deployment_user = "inboxready-deploy"
  host_tag_name   = "${var.name_prefix}-host"
  non_public_source_cidrs = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
  ]
}

resource "digitalocean_tag" "app" {
  name = local.host_tag_name
}

resource "digitalocean_firewall" "app" {
  name = "${var.name_prefix}-firewall"
  tags = [digitalocean_tag.app.name]

  dynamic "inbound_rule" {
    for_each = var.disable_public_ssh ? [] : [1]

    content {
      protocol         = "tcp"
      port_range       = "22"
      source_addresses = sort(tolist(var.operator_ssh_cidrs))
    }
  }

  dynamic "inbound_rule" {
    for_each = length(var.tailscale_direct_peer_cidrs) == 0 ? [] : [1]

    content {
      protocol         = "udp"
      port_range       = "41641"
      source_addresses = sort(tolist(var.tailscale_direct_peer_cidrs))
    }
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "80"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "443"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "123"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "3478"
    destination_addresses = ["0.0.0.0/0"]
  }

  dynamic "outbound_rule" {
    for_each = length(var.tailscale_direct_peer_cidrs) == 0 ? [] : [1]

    content {
      protocol              = "udp"
      port_range            = "1-65535"
      destination_addresses = sort(tolist(var.tailscale_direct_peer_cidrs))
    }
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0"]
  }

  lifecycle {
    precondition {
      condition = (
        var.disable_public_ssh && length(var.operator_ssh_cidrs) == 0 ||
        !var.disable_public_ssh && length(var.operator_ssh_cidrs) > 0
      )
      error_message = "Bootstrap requires at least one explicit operator SSH CIDR. To remove public SSH after verifying Tailscale and recovery access, set disable_public_ssh=true and operator_ssh_cidrs=[]."
    }

    precondition {
      condition = alltrue([
        for source in setunion(
          var.operator_ssh_cidrs,
          var.tailscale_direct_peer_cidrs,
          ) : alltrue([
            for blocked in local.non_public_source_cidrs :
            !cidrcontains(blocked, cidrhost(source, 0))
        ])
      ])
      error_message = "Inbound source CIDRs must be publicly routable; private, shared, loopback, link-local, documentation, multicast, and reserved ranges are rejected."
    }
  }
}

resource "digitalocean_droplet" "app" {
  name   = "${var.name_prefix}-01"
  image  = "ubuntu-24-04-x64"
  region = var.region
  size   = var.droplet_size

  ssh_keys          = sort(tolist(var.ssh_key_ids_or_fingerprints))
  tags              = [digitalocean_tag.app.id]
  backups           = true
  monitoring        = true
  droplet_agent     = true
  ipv6              = false
  public_networking = true
  resize_disk       = false
  graceful_shutdown = true

  backup_policy {
    plan    = "weekly"
    weekday = "SUN"
    hour    = 4
  }

  user_data = templatefile("${path.module}/cloud-init.tftpl", {
    deployment_user  = local.deployment_user
    deployment_group = local.deployment_user
  })

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.confirm_billable_resources
      error_message = "Set confirm_billable_resources=true only after reviewing the plan, current DigitalOcean charges, and state protections."
    }
  }

  depends_on = [digitalocean_firewall.app]
}

resource "digitalocean_project" "app" {
  name        = var.name_prefix
  description = "Single-host private InboxReady production deployment."
  purpose     = "Web Application"
  environment = "Production"
  resources   = [digitalocean_droplet.app.urn]
}
