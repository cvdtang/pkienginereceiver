# Revokes leaf certificates so the base and delta CRLs list entries.
#
# Delta CRLs require auto_rebuild, which only rebuilds a CRL periodically,
# so each revocation is followed by an explicit rebuild:
# the "base" leaf is revoked before crl/rotate and lands in the base CRL,
# the "delta" leaf is revoked afterwards and only lands in the delta CRL via crl/rotate-delta.

locals {
  revoked_crls = ["base", "delta"]
}

resource "vault_pki_secret_backend_cert" "standalone_revoked" {
  for_each = var.revocations ? {
    for pair in setproduct(range(var.num_standalone), local.revoked_crls) :
    "${pair[0]}-${pair[1]}" => {
      role_idx = pair[0]
      crl      = pair[1]
    }
  } : {}

  namespace = local.namespace
  backend   = vault_mount.pki_standalone.path
  depends_on = [vault_pki_secret_backend_config_urls.standalone]

  name        = vault_pki_secret_backend_role.standalone[each.value.role_idx].name
  common_name = "revoked-${each.value.crl}.role-${each.value.role_idx}.example.org"
}

resource "vault_pki_secret_backend_cert" "ica_revoked" {
  for_each = var.revocations ? {
    for pair in setproduct(range(var.num_two_tier), local.revoked_crls) :
    "${pair[0]}-${pair[1]}" => {
      role_idx = pair[0]
      crl      = pair[1]
    }
  } : {}

  namespace = local.namespace
  backend   = vault_mount.pki_ica[each.value.role_idx].path

  name        = vault_pki_secret_backend_role.ica[each.value.role_idx].name
  common_name = "revoked-${each.value.crl}.role-${each.value.role_idx}.example.org"
}

resource "terraform_data" "revoke_standalone" {
  count = var.revocations && var.num_standalone > 0 ? 1 : 0

  triggers_replace = [
    local.ns_path,
    [for k, c in vault_pki_secret_backend_cert.standalone_revoked : c.serial_number],
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/revoke.sh.tftpl", {
      api           = "${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_standalone.path}"
      base_serials  = [for k, c in vault_pki_secret_backend_cert.standalone_revoked : c.serial_number if endswith(k, "-base")]
      delta_serials = [for k, c in vault_pki_secret_backend_cert.standalone_revoked : c.serial_number if endswith(k, "-delta")]
    })
  }

  # Revoke once the issuers and their delta CRL distribution points are final.
  depends_on = [terraform_data.delta_crl_standalone]
}

resource "terraform_data" "revoke_ica" {
  count = var.revocations ? var.num_two_tier : 0

  triggers_replace = [
    local.ns_path,
    vault_pki_secret_backend_cert.ica_revoked["${count.index}-base"].serial_number,
    vault_pki_secret_backend_cert.ica_revoked["${count.index}-delta"].serial_number,
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/revoke.sh.tftpl", {
      api           = "${var.secret_store_host}/v1/${local.ns_path}${vault_mount.pki_ica[count.index].path}"
      base_serials  = [vault_pki_secret_backend_cert.ica_revoked["${count.index}-base"].serial_number]
      delta_serials = [vault_pki_secret_backend_cert.ica_revoked["${count.index}-delta"].serial_number]
    })
  }

  depends_on = [terraform_data.delta_crl_ica]
}
