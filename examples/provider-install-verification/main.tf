terraform {
  required_providers {
    ubyon = {
      source  = "Ubyon/ubyon"
      version = "0.1.5"
    }
  }
}

resource "ubyon_app" "sshservereg58" {
  name              = "sshservereg58"
  category          = "INFRASTRUCTURE"
  sub_category      = "MACHINE"
  app_type          = "PRIVATE"
  auth_provider_ids = ["376d49e7850311eeb6b73e43327e90ca"]
  endpoints = [
    {
      endpoint = {
        access_type = "NATIVE"
        protocol    = "SSH"
        addr = {
          type  = "FQDN"
          value = "sshservereg58.ubyon.com"
        }
        port = {
          type  = "INDIVIDUAL"
          value = 22
        }
        source = "MANUAL"
        attributes = {
          ssh_attributes = {
            ssh_proxy = "ENABLED"
            ub_client = "ENABLED"
          }
        }
      }
    }
  ]
  network_ids = ["376cae20850311eeb6b73e43327e90ca"]
}

resource "ubyon_app" "sshservereg59" {
  name              = "sshservereg59"
  category          = "INFRASTRUCTURE"
  sub_category      = "MACHINE"
  app_type          = "PRIVATE"
  auth_provider_ids = ["376d49e7850311eeb6b73e43327e90ca"]
  endpoints = [
    {
      endpoint = {
        access_type = "NATIVE"
        protocol    = "SSH"
        addr = {
          type  = "FQDN"
          value = "sshservereg59.ubyon.com"
        }
        port = {
          type  = "INDIVIDUAL"
          value = 22
        }
        source = "MANUAL"
        attributes = {
          ssh_attributes = {
            ssh_proxy = "ENABLED"
            ub_client = "DISABLED"
          }
        }
      }
    }
  ]
  network_ids = ["376cae20850311eeb6b73e43327e90ca"]
}

resource "ubyon_ssh_app" "sshservereg55" {
  name = "sshservereg55"
  addr = "sshservereg55.ubyon.com"
  port = 22
  attributes = {
    ssh_proxy = "ENABLED"
    ub_client = "DISABLED"
  }
  auth_provider_ids = ["376d49e7850311eeb6b73e43327e90ca"]
  network_id        = "376cae20850311eeb6b73e43327e90ca"
}

resource "ubyon_ssh_app" "sshservereg57" {
  name = "sshservereg57"
  addr = "sshservereg57.ubyon.com"
  port = 22
  attributes = {
    ssh_proxy = "ENABLED"
    ub_client = "DISABLED"
  }
  auth_provider_ids = ["376d49e7850311eeb6b73e43327e90ca"]
  connector_ids     = ["7bba1178e73711ee91053e43327e90ca"]
}

resource "ubyon_web_app" "webapp1" {
  name              = "webapp1"
  addr              = "webapp1.ubyon.com"
  port              = 443
  protocol          = "HTTPS"
  app_type          = "PUBLIC"
  auth_provider_ids = ["376d49e7850311eeb6b73e43327e90ca"]
  connector_ids     = ["7bba1178e73711ee91053e43327e90ca"]
  browser_access_settings = {
    port         = 80
    hosting_type = "UBYON"
    url_alias_settings = {
      cert_id = "5ee26b92850411eeb6b73e43327e90ca"
      cname   = "wepapp1.ubyon-demo01.integ4.access.ubyon.com"
    }
    https_attributes = {
      start_uri = "/tr1"
    }
  }
  app_tag_ids = ["393c1670b50911eeb6b73e43327e90ca"]
}
