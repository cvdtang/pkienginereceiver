

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.8.0"
    }
  }
}

provider "vault" {}

provider "kubernetes" {
  config_path    = "../../kubeconfig.yaml"
  config_context = "default"
}
