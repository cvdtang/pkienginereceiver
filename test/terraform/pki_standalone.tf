resource "vault_mount" "pki_standalone" {
  namespace = local.namespace

  path = "pki/standalone"
  type = "pki"

  allowed_response_headers    = ["Last-Modified"]
  passthrough_request_headers = ["If-Modified-Since"]
}

resource "vault_pki_secret_backend_config_cluster" "standalone" {
  namespace = local.namespace
  backend   = vault_mount.pki_standalone.path

  // {{cluster_path}}:
  path = "${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_standalone.path}"
}

resource "vault_pki_secret_backend_crl_config" "standalone" {
  namespace = local.namespace

  backend      = vault_mount.pki_standalone.path
  expiry       = "72h"
  disable      = false
  auto_rebuild = true
}

resource "vault_pki_secret_backend_root_cert" "standalone" {

  count     = var.num_standalone
  namespace = local.namespace

  backend     = vault_mount.pki_standalone.path
  type        = "internal" # Vault generates the key
  common_name = "ACME Standalone CA ${count.index}"
  format      = "pem"
  key_type    = "ec"
  key_bits    = 224

  not_before_duration = local.not_before
  not_after           = local.not_after
}

resource "vault_pki_secret_backend_issuer" "standalone" {
  count     = var.num_standalone
  namespace = local.namespace

  backend                   = vault_mount.pki_standalone.path
  issuer_ref                = vault_pki_secret_backend_root_cert.standalone[count.index].issuer_id
  issuer_name               = "acme-standalone-issuer-${count.index}"
  enable_aia_url_templating = true

  crl_distribution_points = [
    "{{cluster_path}}/issuer/{{issuer_id}}/crl/der",
    "{{cluster_path}}/issuer/{{issuer_id}}/crl/pem",

    # Non-existent endpoint to test processing_status=0 (fetch_failed)
    "{{cluster_path}}/issuer/{{issuer_id}}/crl/fake",

    # Unauthenticated endpoint to test processing_status=1 (parse_failed)
    "{{cluster_path}}/issuer/{{issuer_id}}/json",
  ]

  ## https://github.com/hashicorp/terraform-provider-vault/pull/2761
  # delta_crl_distribution_points = [
  #   "{{cluster_path}}/issuer/{{issuer_id}}/crl/delta/der",
  # ]
}
resource "vault_pki_secret_backend_role" "standalone" {
  count     = var.num_standalone
  namespace = local.namespace

  backend          = vault_mount.pki_standalone.path
  issuer_ref       = vault_pki_secret_backend_issuer.standalone[count.index].issuer_id
  name             = "acme-standalone-role-${count.index}"
  ttl              = 3600
  key_type         = "ec"
  key_bits         = 224
  allowed_domains  = ["example.org"]
  allow_subdomains = true
}

resource "vault_pki_secret_backend_cert" "standalone" {
  for_each = {
    for pair in setproduct(range(var.num_standalone), range(var.num_leaf)) :
    "${pair[0]}-${pair[1]}" => {
      role_idx = pair[0]
      leaf_idx = pair[1]
    }
  }

  namespace = local.namespace
  backend   = vault_mount.pki_standalone.path

  name = vault_pki_secret_backend_role.standalone[each.value.role_idx].name

  common_name = "leaf-${each.value.leaf_idx}.role-${each.value.role_idx}.example.org"
}
