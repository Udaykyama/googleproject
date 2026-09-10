terraform {
  required_version = "= 1.12.6"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "= 2.100.0"
    }
  }
}
