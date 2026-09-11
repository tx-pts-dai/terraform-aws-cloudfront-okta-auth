variable "okta_client_id" {
  description = "Client ID of the Okta OIDC web application."
  type        = string
}

variable "okta_client_secret" {
  description = "Client secret of the Okta OIDC web application. Pass it at runtime, e.g. TF_VAR_okta_client_secret; it is never written to state."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "okta_client_secret_version" {
  description = "Increment after rotating the client secret in Okta."
  type        = number
  default     = 1
}

variable "okta_issuer" {
  description = "Okta issuer URL, e.g. https://acme.okta.com or https://acme.okta.com/oauth2/default."
  type        = string
}
