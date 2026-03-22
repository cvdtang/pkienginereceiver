resource "vault_auth_backend" "kubernetes" {
  count     = var.kubernetes ? 1 : 0
  namespace = local.namespace

  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "config" {
  count     = var.kubernetes ? 1 : 0
  namespace = local.namespace

  backend            = vault_auth_backend.kubernetes[0].path
  kubernetes_host    = var.kubernetes_host
  kubernetes_ca_cert = var.kubernetes_ca_crt
  token_reviewer_jwt = var.kubernetes_token_reviewer_jwt
}

resource "vault_kubernetes_auth_backend_role" "app_role" {
  count     = var.kubernetes ? 1 : 0
  namespace = local.namespace

  backend                          = vault_auth_backend.kubernetes[0].path
  role_name                        = "otel-collector"
  bound_service_account_names      = ["otel-collector"]
  bound_service_account_namespaces = ["default"]
  token_ttl                        = var.auth_token_ttl
  token_max_ttl                    = var.auth_token_max_ttl
  token_policies                   = ["default", vault_policy.this.name]
}
