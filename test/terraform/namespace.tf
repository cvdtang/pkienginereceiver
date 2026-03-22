resource "vault_namespace" "tenant" {
  count = var.namespaced ? 1 : 0
  path  = "tenant-a"
}
