

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.13.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "3.3.0"
    }
  }
}

provider "kubernetes" {
  config_path    = "../../kubeconfig.yaml"
  config_context = "default"
}
