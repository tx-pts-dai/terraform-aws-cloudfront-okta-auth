variable "okta_client_id" {
  description = "Client ID of the Okta OIDC web application."
  type        = string

  validation {
    condition     = length(var.okta_client_id) > 0
    error_message = "okta_client_id must not be empty."
  }
}

variable "okta_client_secret" {
  description = "Client secret of the Okta OIDC web application. Stored as an SSM SecureString parameter in us-east-1."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.okta_client_secret) > 0
    error_message = "okta_client_secret must not be empty."
  }
}

variable "okta_issuer" {
  description = "Okta issuer URL without trailing slash: the org authorization server (https://acme.okta.com) or a custom authorization server (https://acme.okta.com/oauth2/default)."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+(/oauth2/[^/]+)?$", var.okta_issuer))
    error_message = "okta_issuer must look like https://<domain> or https://<domain>/oauth2/<authServerId> with no trailing slash."
  }
}

variable "name" {
  description = "Name of the Lambda@Edge function, IAM role and SSM parameter prefix."
  type        = string
  default     = "cloudfront-okta-auth"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,64}$", var.name))
    error_message = "name must be 1-64 characters of letters, digits, hyphens or underscores."
  }
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
