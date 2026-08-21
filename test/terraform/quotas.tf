# Enables the secret store rate limit quota response headers.
# There is no Terraform provider resource for /sys/quotas/config.
# ref: https://github.com/hashicorp/terraform-provider-vault/issues/1774
resource "terraform_data" "enable_rate_limit_response_headers" {
  triggers_replace = "enable_rate_limit_response_headers"

  provisioner "local-exec" {
    command = <<-EOT
      curl --fail --silent --show-error \
        -X POST \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"enable_rate_limit_response_headers": true}' \
        "${var.secret_store_host}/v1/sys/quotas/config"
    EOT
  }
}

# Applies a 1 request/s rate limit quota to the standalone PKI mount when
# rate_limit_standalone is set. Used by the rate limit integration test.
# Quota management endpoints are only available in the root namespace.
resource "vault_quota_rate_limit" "standalone" {
  count = var.rate_limit_standalone ? 1 : 0

  name     = "standalone-rate-limit"
  path     = "${local.ns_path}${vault_mount.pki_standalone.path}"
  rate     = 1
  interval = 1

  depends_on = [
    terraform_data.enable_rate_limit_response_headers,
    vault_pki_secret_backend_cert.standalone,
    vault_pki_secret_backend_issuer.standalone,
  ]
}
