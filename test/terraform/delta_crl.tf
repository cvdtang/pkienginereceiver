# Configures delta CRL distribution points on the issuers via curl.
# There is no Terraform provider resource for delta_crl_distribution_points
# on issuers.
# ref: https://github.com/hashicorp/terraform-provider-vault/pull/2761
#
# Only the PATCH issuer endpoint applies delta_crl_distribution_points and it
# requires the application/merge-patch+json content type, so a plain curl with
# those headers is used.
resource "terraform_data" "delta_crl_standalone" {
  count = var.num_standalone

  triggers_replace = local.ns_path

  provisioner "local-exec" {
    command = <<-EOT
      curl --fail --silent --show-error \
        -X PATCH \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        -H "Content-Type: application/merge-patch+json" \
        -d '{"delta_crl_distribution_points": ["{{cluster_path}}/issuer/{{issuer_id}}/crl/delta/der", "{{cluster_path}}/issuer/{{issuer_id}}/crl/delta/pem"]}' \
        "${var.secret_store_host}/v1/${local.ns_path}pki/standalone/issuer/acme-standalone-issuer-${count.index}"
    EOT
  }

  depends_on = [
    vault_pki_secret_backend_issuer.standalone,
  ]
}

resource "terraform_data" "delta_crl_ica" {
  count = var.num_two_tier

  triggers_replace = local.ns_path

  provisioner "local-exec" {
    command = <<-EOT
      curl --fail --silent --show-error \
        -X PATCH \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        -H "Content-Type: application/merge-patch+json" \
        -d '{"delta_crl_distribution_points": ["{{cluster_path}}/issuer/{{issuer_id}}/crl/delta/der", "{{cluster_path}}/issuer/{{issuer_id}}/crl/delta/pem"]}' \
        "${var.secret_store_host}/v1/${local.ns_path}pki/ica_${count.index}/issuer/acme-intermediate-issuer-${count.index}"
    EOT
  }

  depends_on = [
    vault_pki_secret_backend_issuer.ica,
  ]
}

# The root issuer must be configured before the intermediate is signed so the
# ICA certificate carries the per-issuer base and delta CRL distribution point.
resource "terraform_data" "delta_crl_root" {
  count = local.create_root

  triggers_replace = local.ns_path

  provisioner "local-exec" {
    command = <<-EOT
      curl --fail --silent --show-error \
        -X PATCH \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        -H "Content-Type: application/merge-patch+json" \
        -d '{"crl_distribution_points": ["${var.secret_store_host}/v1/${local.ns_path}pki/root/issuer/root-v1/crl/der", "${var.secret_store_host}/v1/${local.ns_path}pki/root/issuer/root-v1/crl/pem"], "delta_crl_distribution_points": ["${var.secret_store_host}/v1/${local.ns_path}pki/root/issuer/root-v1/crl/delta/der", "${var.secret_store_host}/v1/${local.ns_path}pki/root/issuer/root-v1/crl/delta/pem"]}' \
        "${var.secret_store_host}/v1/${local.ns_path}pki/root/issuer/root-v1"
    EOT
  }

  depends_on = [
    vault_pki_secret_backend_issuer.root,
  ]
}
