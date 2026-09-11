mock_provider "aws" {
  override_data {
    target = data.aws_region.current
    values = {
      region = "us-east-1"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }
}

variables {
  okta_client_id     = "0oa123"
  okta_client_secret = "secret"
  okta_issuer        = "https://acme.okta.com"
}

run "lambda_edge_function" {
  command = plan

  assert {
    condition     = aws_lambda_function.this.publish == true
    error_message = "Lambda@Edge requires a published version"
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "nodejs22.x"
    error_message = "Unexpected runtime"
  }

  assert {
    condition     = aws_lambda_function.this.handler == "index.handler"
    error_message = "Unexpected handler"
  }

  assert {
    condition     = aws_lambda_function.this.timeout <= 5 && aws_lambda_function.this.memory_size <= 128
    error_message = "Viewer-request Lambda@Edge functions are limited to 5 s and 128 MB"
  }

  assert {
    condition     = aws_lambda_function.this.function_name == "cloudfront-okta-auth"
    error_message = "Default name not applied"
  }
}

run "iam_role" {
  command = plan

  assert {
    condition     = strcontains(aws_iam_role.this.assume_role_policy, "edgelambda.amazonaws.com") && strcontains(aws_iam_role.this.assume_role_policy, "lambda.amazonaws.com")
    error_message = "Role must be assumable by both lambda.amazonaws.com and edgelambda.amazonaws.com"
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.this.policy, "arn:aws:logs:*:123456789012:log-group:/aws/lambda/*.cloudfront-okta-auth:*")
    error_message = "Log permissions must cover every region's replica log group"
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.this.policy, "ssm:GetParameter")
    error_message = "Role must be able to read the client secret parameter"
  }
}

run "client_secret_parameter" {
  command = plan

  assert {
    condition     = aws_ssm_parameter.client_secret.type == "SecureString"
    error_message = "Client secret must be a SecureString"
  }

  assert {
    condition     = aws_ssm_parameter.client_secret.name == "/cloudfront-okta-auth/okta-client-secret"
    error_message = "Unexpected parameter name"
  }
}

run "org_authorization_server_endpoints" {
  command = plan

  assert {
    condition     = output.okta_endpoints.authorize == "https://acme.okta.com/oauth2/v1/authorize"
    error_message = "Org authorization server endpoints live under /oauth2/v1"
  }

  assert {
    condition     = output.okta_endpoints.token == "https://acme.okta.com/oauth2/v1/token"
    error_message = "Unexpected token endpoint"
  }

  assert {
    condition     = anytrue([for s in data.archive_file.this.source : strcontains(s.content, "\"authorize_endpoint\":\"https://acme.okta.com/oauth2/v1/authorize\"")])
    error_message = "Rendered config.mjs must contain the derived authorize endpoint"
  }

  assert {
    condition     = anytrue([for s in data.archive_file.this.source : strcontains(s.content, "\"issuer\":\"https://acme.okta.com\"")])
    error_message = "Rendered config.mjs must contain the issuer verbatim for iss validation"
  }
}

run "custom_authorization_server_endpoints" {
  command = plan

  variables {
    okta_issuer = "https://acme.okta.com/oauth2/default"
  }

  assert {
    condition     = output.okta_endpoints.authorize == "https://acme.okta.com/oauth2/default/v1/authorize"
    error_message = "Custom authorization server endpoints live under the issuer"
  }

  assert {
    condition     = output.okta_endpoints.keys == "https://acme.okta.com/oauth2/default/v1/keys"
    error_message = "Unexpected JWKS endpoint"
  }
}

run "paths_and_bundle" {
  command = plan

  assert {
    condition     = output.callback_path == "/_auth/callback" && output.logout_path == "/_auth/logout"
    error_message = "Unexpected auth paths"
  }

  assert {
    condition     = toset([for s in data.archive_file.this.source : s.filename]) == toset(["index.mjs", "auth.mjs", "config.mjs"])
    error_message = "Bundle must contain exactly index.mjs, auth.mjs and config.mjs"
  }
}

run "custom_name" {
  command = plan

  variables {
    name = "docs-auth"
  }

  assert {
    condition     = aws_lambda_function.this.function_name == "docs-auth" && aws_iam_role.this.name == "docs-auth" && aws_ssm_parameter.client_secret.name == "/docs-auth/okta-client-secret"
    error_message = "name must be applied to the function, role and parameter"
  }
}
