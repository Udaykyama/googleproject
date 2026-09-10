variable "name_prefix" {
  description = "Lowercase prefix used for the DigitalOcean project, tag, Droplet, and firewall."
  type        = string
  default     = "inboxready-production"

  validation {
    condition = (
      length(var.name_prefix) >= 3 &&
      length(var.name_prefix) <= 48 &&
      can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.name_prefix))
    )
    error_message = "name_prefix must be 3-48 lowercase letters, digits, or hyphens and cannot start or end with a hyphen."
  }
}

variable "region" {
  description = "DigitalOcean region slug. Confirm availability and latency before apply."
  type        = string
  default     = "nyc3"

  validation {
    condition     = can(regex("^[a-z]{3}[0-9]+$", var.region))
    error_message = "region must be a DigitalOcean region slug such as nyc3, sfo3, or lon1."
  }
}

variable "droplet_size" {
  description = "Bounded basic Droplet size. Review current DigitalOcean pricing before apply."
  type        = string
  default     = "s-1vcpu-2gb"

  validation {
    condition = contains([
      "s-1vcpu-1gb",
      "s-1vcpu-2gb",
      "s-2vcpu-4gb",
    ], var.droplet_size)
    error_message = "droplet_size must be one of the reviewed modest basic sizes."
  }
}

variable "ssh_key_ids_or_fingerprints" {
  description = "Non-empty set of existing DigitalOcean SSH public-key IDs or MD5 fingerprints. Private keys are never accepted."
  type        = set(string)

  validation {
    condition = (
      length(var.ssh_key_ids_or_fingerprints) > 0 &&
      alltrue([
        for key in var.ssh_key_ids_or_fingerprints :
        can(regex("^([0-9]+|([0-9A-Fa-f]{2}:){15}[0-9A-Fa-f]{2})$", key))
      ])
    )
    error_message = "Provide at least one existing numeric DigitalOcean SSH key ID or 16-byte colon-delimited fingerprint."
  }
}

variable "operator_ssh_cidrs" {
  description = "Explicit IPv4 CIDRs allowed to use public SSH. Required for bootstrap unless disable_public_ssh is deliberately enabled later."
  type        = set(string)

  validation {
    condition = alltrue([
      for cidr in var.operator_ssh_cidrs :
      can(cidrnetmask(cidr)) &&
      try(tonumber(split("/", cidr)[1]), 0) >= 24 &&
      try(tonumber(split("/", cidr)[1]), 33) <= 32
    ])
    error_message = "operator_ssh_cidrs must contain IPv4 /24-/32 CIDRs; 0.0.0.0/0 and broad networks are rejected."
  }
}

variable "disable_public_ssh" {
  description = "Remove the public SSH rule only after Tailscale SSH, sudo/recovery access, and the provider console are verified."
  type        = bool
  default     = false
}

variable "tailscale_direct_peer_cidrs" {
  description = "Optional bounded public IPv4 CIDRs for direct Tailscale UDP. Empty uses TCP 443 DERP fallback."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.tailscale_direct_peer_cidrs :
      can(cidrnetmask(cidr)) &&
      try(tonumber(split("/", cidr)[1]), 0) >= 24 &&
      try(tonumber(split("/", cidr)[1]), 33) <= 32
    ])
    error_message = "tailscale_direct_peer_cidrs may be empty or contain only explicit IPv4 /24-/32 peer networks."
  }
}

variable "confirm_billable_resources" {
  description = "Must be set to true only after reviewing the plan, current pricing, backup charges, and state storage."
  type        = bool
  default     = false
}
