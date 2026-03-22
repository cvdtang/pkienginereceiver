locals {
  not_before = "10m"
  not_after  = "2035-12-31T23:59:59Z"

  namespace = try(vault_namespace.tenant[0].path_fq, null)
  ns_path   = try("${vault_namespace.tenant[0].path}/", "")

  create_root = var.num_two_tier > 0 ? 1 : 0
}