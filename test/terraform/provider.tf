

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.10.1"
    }
  }
}

provider "vault" {}

provider "kubernetes" {
  config_path    = "../../kubeconfig.yaml"
  config_context = "default"
}
