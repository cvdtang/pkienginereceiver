/*
    Setup root
*/
resource "vault_mount" "pki_root" {
  count     = local.create_root
  namespace = local.namespace

  path = "pki/root"
  type = "pki"

  allowed_response_headers    = ["Last-Modified"]
  passthrough_request_headers = ["If-Modified-Since"]
}

resource "vault_pki_secret_backend_config_urls" "root" {
  count     = local.create_root
  namespace = local.namespace

  backend                 = vault_mount.pki_root[0].path
  crl_distribution_points = ["${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_root[0].path}/crl"]
  # delta_crl_distribution_points = ["${var.secret_store_host}/v1/${vault_mount.pki_root[0].path}/crl/delta"]
}

resource "vault_pki_secret_backend_crl_config" "root" {
  count     = local.create_root
  namespace = local.namespace

  backend      = vault_mount.pki_root[0].path
  expiry       = "72h"
  disable      = false
  auto_rebuild = true
  enable_delta = true
}

resource "vault_pki_secret_backend_root_cert" "root" {
  depends_on = [vault_pki_secret_backend_config_urls.root]
  count      = local.create_root
  namespace  = local.namespace

  backend     = vault_mount.pki_root[0].path
  type        = "internal"
  common_name = "ACME root v1"
  issuer_name = "root-v1"

  not_before_duration = local.not_before
  not_after           = local.not_after
}

resource "vault_pki_secret_backend_issuer" "root" {
  count     = local.create_root
  namespace = local.namespace

  backend     = vault_mount.pki_root[0].path
  issuer_ref  = vault_pki_secret_backend_root_cert.root[0].issuer_id
  issuer_name = vault_pki_secret_backend_root_cert.root[0].issuer_name
}

/*
    Setup intermediates
*/
resource "vault_mount" "pki_ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  path = "pki/ica_${count.index}"
  type = "pki"

  allowed_response_headers    = ["Last-Modified"]
  passthrough_request_headers = ["If-Modified-Since"]
}

resource "vault_pki_secret_backend_config_cluster" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend = vault_mount.pki_ica[count.index].path

  // {{cluster_path}}:
  path = "${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_ica[count.index].path}"
}

resource "vault_pki_secret_backend_config_urls" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend                 = vault_mount.pki_ica[count.index].path
  crl_distribution_points = ["${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_ica[count.index].path}/crl"]
  # delta_crl_distribution_points = ["${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_ica[count.index].path}/crl/delta"]
}

resource "vault_pki_secret_backend_crl_config" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend      = vault_mount.pki_ica[count.index].path
  expiry       = "72h"
  disable      = false
  auto_rebuild = true
  enable_delta = true
}

resource "vault_pki_secret_backend_intermediate_cert_request" "ica" {
  count      = var.num_two_tier
  namespace  = local.namespace
  depends_on = [vault_pki_secret_backend_config_urls.ica]

  backend     = vault_mount.pki_ica[count.index].path
  type        = "internal"
  common_name = "ACME intermediate ${count.index}"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend     = vault_mount.pki_root[0].path
  common_name = "ACME intermediate ${count.index}"
  csr         = vault_pki_secret_backend_intermediate_cert_request.ica[count.index].csr
  format      = "pem_bundle"
  ttl         = 154800000
  issuer_ref  = vault_pki_secret_backend_root_cert.root[0].issuer_id
}

resource "vault_pki_secret_backend_intermediate_set_signed" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend     = vault_mount.pki_ica[count.index].path
  certificate = vault_pki_secret_backend_root_sign_intermediate.ica[count.index].certificate
}

resource "vault_pki_secret_backend_issuer" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend                   = vault_mount.pki_ica[count.index].path
  issuer_ref                = vault_pki_secret_backend_intermediate_set_signed.ica[count.index].imported_issuers[0]
  issuer_name               = "acme-intermediate-issuer-${count.index}"
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

resource "vault_pki_secret_backend_role" "ica" {
  count     = var.num_two_tier
  namespace = local.namespace

  backend          = vault_mount.pki_ica[count.index].path
  issuer_ref       = vault_pki_secret_backend_issuer.ica[count.index].issuer_id
  name             = "acme-intermediate-role-${count.index}"
  ttl              = 3600
  key_type         = "ec"
  key_bits         = 224
  allowed_domains  = ["example.org"]
  allow_subdomains = true
}

resource "vault_pki_secret_backend_cert" "ica" {
  for_each = {
    for pair in setproduct(range(var.num_two_tier), range(var.num_leaf)) :
    "${pair[0]}-${pair[1]}" => {
      role_idx = pair[0]
      leaf_idx = pair[1]
    }
  }

  namespace = local.namespace
  backend   = vault_mount.pki_ica[each.value.role_idx].path

  name = vault_pki_secret_backend_role.ica[each.value.role_idx].name

  common_name = "leaf-${each.value.leaf_idx}.role-${each.value.role_idx}.example.org"
}
