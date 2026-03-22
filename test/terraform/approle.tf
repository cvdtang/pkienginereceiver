resource "vault_auth_backend" "approle" {
  namespace = local.namespace
  type      = "approle"
}

resource "vault_approle_auth_backend_role" "this" {
  namespace = local.namespace

  backend        = vault_auth_backend.approle.path
  role_name      = "test-role"
  token_policies = ["default", vault_policy.this.name]

  # Set value for ease of testing
  role_id = "my-role-id"

  token_ttl     = var.auth_token_ttl
  token_max_ttl = var.auth_token_max_ttl
}

resource "vault_approle_auth_backend_role_secret_id" "this" {
  namespace = local.namespace

  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.this.role_name

  # Set value for ease of testing
  secret_id = "my-secret-id"
}
