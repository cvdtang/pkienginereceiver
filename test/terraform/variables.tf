variable "secret_store_host" {
  description = "The address of the secret store"
  type        = string
  default     = "http://127.0.0.1:8200"
}

variable "kubernetes_host" {
  description = "The address of the Kubernetes API server"
  type        = string
  default     = "https://127.0.0.1:6443"
}

variable "kubernetes" {
  description = "Enable Kubernetes auth engine"
  type        = bool
  default     = false
}

variable "namespaced" {
  description = "Create namespaced resources"
  type        = bool
  default     = false
}

variable "kubernetes_ca_crt" {
  description = "Used by Kubernetes auth engine"
  type        = string
  default     = ""
}


variable "kubernetes_token_reviewer_jwt" {
  description = "Used by Kubernetes auth engine"
  type        = string
  default     = ""
}

variable "jwt" {
  description = "Enable JWT auth engine"
  type        = bool
  default     = false
}

variable "jwt_issuer" {
  description = "Issuer claim for JWT auth engine"
  type        = string
  default     = ""
}

variable "jwt_validation_pubkeys" {
  description = "PEM encoded public key used to validate JWTs"
  type        = string
  default     = ""
}

variable "jwt_audience" {
  description = "Audience claim for JWT auth engine (optional)"
  type        = string
  default     = ""
}

variable "auth_token_ttl" {
  description = "TTL for tokens issued by auth backends"
  type        = number
  default     = null
}

variable "auth_token_max_ttl" {
  description = "Max TTL for tokens issued by auth backends"
  type        = number
  default     = null
}

variable "num_two_tier" {
  description = "Number of two-tier CA setup (1 root CA, N ICA)"
  type        = number
  default     = 1
}

variable "num_standalone" {
  description = "Number of standalone CAs"
  type        = number
  default     = 1
}

variable "num_leaf" {
  description = "Number of issued certificates per issuing issuer"
  type        = number
  default     = 1
}
