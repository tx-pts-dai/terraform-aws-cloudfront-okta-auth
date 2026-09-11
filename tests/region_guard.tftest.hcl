mock_provider "aws" {
  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
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

run "rejects_non_us_east_1_provider" {
  command = plan

  expect_failures = [data.aws_region.current]
}
