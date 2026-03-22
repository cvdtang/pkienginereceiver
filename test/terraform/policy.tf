resource "vault_policy" "this" {
  namespace = local.namespace

  name = "pkiengine"

  policy = <<EOT
path "sys/mounts" {
  capabilities = [ "read" ]
}

path "pki/+/config/cluster" {
  capabilities = [ "read" ]
}

path "pki/+/certs" {
  capabilities = [ "list" ]
}

path "pki/+/issuer/+" {
  capabilities = [ "read" ]
}
EOT
}
