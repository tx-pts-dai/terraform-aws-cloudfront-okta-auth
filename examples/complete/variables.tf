variable "okta_client_id" {
  description = "Client ID of the Okta OIDC web application."
  type        = string
}

variable "okta_client_secret" {
  description = "Client secret of the Okta OIDC web application."
  type        = string
  sensitive   = true
}

variable "okta_issuer" {
  description = "Okta issuer URL, e.g. https://acme.okta.com or https://acme.okta.com/oauth2/default."
  type        = string
}
