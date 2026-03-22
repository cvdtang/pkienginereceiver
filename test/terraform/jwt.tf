resource "vault_jwt_auth_backend" "jwt" {
  count                  = var.jwt ? 1 : 0
  namespace              = local.namespace
  path                   = "jwt"
  jwt_validation_pubkeys = [var.jwt_validation_pubkeys]
  bound_issuer           = var.jwt_issuer
}

resource "vault_jwt_auth_backend_role" "role" {
  count          = var.jwt ? 1 : 0
  namespace      = local.namespace
  backend        = vault_jwt_auth_backend.jwt[0].path
  role_name      = "otel-collector"
  token_policies = ["default", vault_policy.this.name]

  user_claim      = "sub"
  role_type       = "jwt"
  bound_audiences = var.jwt_audience == "" ? null : [var.jwt_audience]
  token_ttl       = var.auth_token_ttl
  token_max_ttl   = var.auth_token_max_ttl
  bound_claims = {
    "sub" = "system:serviceaccount:default:otel-collector"
  }
}
