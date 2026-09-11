output "site_url" {
  description = "URL of the protected site."
  value       = "https://${aws_cloudfront_distribution.site.domain_name}/"
}

output "okta_sign_in_redirect_uris" {
  description = "Register these as sign-in redirect URIs on the Okta application."
  value       = ["https://${aws_cloudfront_distribution.site.domain_name}${module.okta_auth.callback_path}"]
}

output "okta_sign_out_redirect_uris" {
  description = "Register these as sign-out redirect URIs on the Okta application."
  value       = ["https://${aws_cloudfront_distribution.site.domain_name}/"]
}
