resource "vault_token_auth_backend_role" "this" {
  namespace = local.namespace

  role_name        = "test-token"
  allowed_policies = ["default", vault_policy.this.name]
  renewable        = true
  token_period     = var.auth_token_ttl
  token_max_ttl    = var.auth_token_max_ttl
}

resource "vault_token" "renewable" {
  namespace = local.namespace

  role_name = vault_token_auth_backend_role.this.role_name
  policies  = ["default", vault_policy.this.name]
  renewable = true
}
