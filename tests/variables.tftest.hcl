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

run "rejects_http_issuer" {
  command = plan

  variables {
    okta_issuer = "http://acme.okta.com"
  }

  expect_failures = [var.okta_issuer]
}

run "rejects_trailing_slash" {
  command = plan

  variables {
    okta_issuer = "https://acme.okta.com/"
  }

  expect_failures = [var.okta_issuer]
}

run "rejects_non_oauth2_path" {
  command = plan

  variables {
    okta_issuer = "https://acme.okta.com/foo"
  }

  expect_failures = [var.okta_issuer]
}

run "rejects_empty_client_id" {
  command = plan

  variables {
    okta_client_id = ""
  }

  expect_failures = [var.okta_client_id]
}

run "rejects_non_integer_secret_version" {
  command = plan

  variables {
    okta_client_secret_version = 1.5
  }

  expect_failures = [var.okta_client_secret_version]
}

run "rejects_long_name" {
  command = plan

  variables {
    name = "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcde"
  }

  expect_failures = [var.name]
}
