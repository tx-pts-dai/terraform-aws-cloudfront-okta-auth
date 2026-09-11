data "aws_caller_identity" "current" {}

data "aws_region" "current" {
  lifecycle {
    postcondition {
      condition     = self.region == "us-east-1"
      error_message = "Lambda@Edge functions must be created in us-east-1. Call this module with providers = { aws = aws.us_east_1 }."
    }
  }
}

locals {
  okta_base      = can(regex("/oauth2/", var.okta_issuer)) ? var.okta_issuer : "${var.okta_issuer}/oauth2"
  callback_path  = "/_auth/callback"
  logout_path    = "/_auth/logout"
  ssm_param_name = "/${var.name}/okta-client-secret"

  okta_endpoints = {
    authorize = "${local.okta_base}/v1/authorize"
    token     = "${local.okta_base}/v1/token"
    keys      = "${local.okta_base}/v1/keys"
    logout    = "${local.okta_base}/v1/logout"
  }

  config = {
    issuer                = var.okta_issuer
    client_id             = var.okta_client_id
    authorize_endpoint    = local.okta_endpoints.authorize
    token_endpoint        = local.okta_endpoints.token
    jwks_endpoint         = local.okta_endpoints.keys
    logout_endpoint       = local.okta_endpoints.logout
    callback_path         = local.callback_path
    logout_path           = local.logout_path
    secret_parameter_name = local.ssm_param_name
    secret_region         = "us-east-1"
    session_cookie        = "__Host-okta_session"
    login_cookie          = "__Host-okta_login"
  }
}

resource "aws_ssm_parameter" "client_secret" {
  name             = local.ssm_param_name
  description      = "Okta client secret read by the ${var.name} Lambda@Edge function"
  type             = "SecureString"
  value_wo         = var.okta_client_secret
  value_wo_version = var.okta_client_secret_version
  tags             = var.tags
}

resource "aws_iam_role" "this" {
  name = var.name
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "this" {
  name = var.name
  role = aws_iam_role.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*.${var.name}:*"
      },
      {
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.ssm_param_name}"
      },
    ]
  })
}

data "archive_file" "this" {
  type             = "zip"
  output_path      = "${path.module}/builds/${var.name}.zip"
  output_file_mode = "0644"

  source {
    filename = "index.mjs"
    content  = file("${path.module}/lambda/index.mjs")
  }

  source {
    filename = "auth.mjs"
    content  = file("${path.module}/lambda/auth.mjs")
  }

  source {
    filename = "config.mjs"
    content  = templatefile("${path.module}/lambda/config.mjs.tftpl", { config_json = jsonencode(local.config) })
  }
}

resource "aws_lambda_function" "this" {
  function_name    = var.name
  description      = "CloudFront viewer-request Okta OIDC gate"
  role             = aws_iam_role.this.arn
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  architectures    = ["x86_64"]
  memory_size      = 128
  timeout          = 5
  publish          = true
  tags             = var.tags

  depends_on = [aws_iam_role_policy.this]
}
