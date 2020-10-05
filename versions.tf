terraform {
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 1.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 2.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 2.0"
    }
  }
  required_version = ">= 0.13"
}
