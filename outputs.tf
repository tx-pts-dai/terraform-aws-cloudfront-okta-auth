output "lambda_qualified_arn" {
  description = "Versioned ARN of the Lambda@Edge function. Use it as lambda_arn in a viewer-request lambda_function_association."
  value       = aws_lambda_function.this.qualified_arn
}

output "lambda_function_arn" {
  description = "Unversioned ARN of the Lambda@Edge function."
  value       = aws_lambda_function.this.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda@Edge function."
  value       = aws_lambda_function.this.function_name
}

output "lambda_role_arn" {
  description = "ARN of the Lambda@Edge execution role."
  value       = aws_iam_role.this.arn
}

output "ssm_parameter_arn" {
  description = "ARN of the SSM SecureString parameter holding the Okta client secret."
  value       = aws_ssm_parameter.client_secret.arn
}

output "callback_path" {
  description = "Path that must be registered in Okta as sign-in redirect URI: https://<site-domain><callback_path>."
  value       = local.callback_path
}

output "logout_path" {
  description = "Path that clears the session and signs the user out of Okta."
  value       = local.logout_path
}

output "okta_endpoints" {
  description = "Okta endpoints derived from okta_issuer."
  value       = local.okta_endpoints
}
