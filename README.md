# Terraform AWS CloudFront Okta Auth

Puts Okta login in front of an existing CloudFront distribution. A single Lambda@Edge viewer-request function runs the OpenID Connect authorization-code flow (with PKCE) against Okta, stores the Okta ID token in a hardened session cookie and verifies its RS256 signature on every request. Unauthenticated visitors are redirected to Okta; everything else, including cached objects, stays behind the gate.

The module only needs the Okta client id, client secret and issuer URL. It creates the Lambda@Edge function, its IAM role and an SSM SecureString parameter for the client secret, all in us-east-1, and returns the versioned function ARN to attach to your distribution.

## Usage

```hcl
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

module "okta_auth" {
  source  = "tx-pts-dai/cloudfront-okta-auth/aws"
  version = "~> 1.0"

  providers = {
    aws = aws.us_east_1
  }

  okta_client_id     = var.okta_client_id
  okta_client_secret = var.okta_client_secret
  okta_issuer        = "https://acme.okta.com" # or https://acme.okta.com/oauth2/default
}

resource "aws_cloudfront_distribution" "site" {
  # ...

  default_cache_behavior {
    # ...
    viewer_protocol_policy = "redirect-to-https"

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.okta_auth.lambda_qualified_arn
      include_body = false
    }
  }
}
```

Then register the redirect URIs on the Okta application (see below) and deploy.

## Okta application setup

Create an OIDC application of type **Web Application** with the **Authorization Code** grant, client authentication **Client secret**, and PKCE allowed. For every domain the distribution serves (custom aliases and, if used, the `*.cloudfront.net` name) register:

| Okta setting | Value |
| --- | --- |
| Sign-in redirect URIs | `https://<domain>/_auth/callback` |
| Sign-out redirect URIs | `https://<domain>/` |

Assign the users or groups that may access the site to the application. Anyone not assigned is rejected by Okta and receives a 403 from the function.

`okta_issuer` is the issuer of the authorization server that signs the ID tokens:

- Org authorization server: `https://acme.okta.com` (endpoints under `https://acme.okta.com/oauth2/v1/`)
- Custom authorization server: `https://acme.okta.com/oauth2/default` (endpoints under the issuer)

## How it works

1. A request without a valid session cookie is answered with a 302 to Okta's authorize endpoint. State, nonce and the PKCE verifier are stored in a short-lived HMAC-signed cookie (`__Host-okta_login`, 10 minutes) together with the originally requested path.
2. Okta redirects back to `/_auth/callback`. The function checks the state, exchanges the code (client secret + PKCE verifier) at the token endpoint, verifies the ID token signature against Okta's JWKS and checks `iss`, `aud`, `exp` and `nonce`.
3. The ID token is stored in `__Host-okta_session` (`HttpOnly; Secure; SameSite=Lax; Path=/`) with `Max-Age` equal to the token lifetime, and the user is redirected to the original path.
4. Every later request verifies the cookie's signature and claims (JWKS cached for one hour per Lambda container), strips the auth cookies and forwards the request to CloudFront. When the token expires the flow starts again; with an active Okta session this is a transparent redirect.
5. `/_auth/logout` clears the cookie and signs the user out of Okta, returning to `https://<domain>/`.

The client secret is read from SSM Parameter Store once per Lambda container. It is never embedded in the function code.

## Wiring notes

- Attach the function to the default cache behavior **and every ordered cache behavior**. Behaviors without the association are unprotected.
- `viewer_protocol_policy` must be `redirect-to-https` or `https-only`; the cookies are `Secure`.
- Do not include the `Cookie` header in the cache key. The managed `CachingOptimized` policy is a good default. Nothing needs to be forwarded to the origin.
- Because the viewer-request event runs before the cache lookup, cached objects are gated too.
- Lambda@Edge cannot log to a single region: each edge region writes to `/aws/lambda/us-east-1.<name>` in its own region. The role allows this for all regions.
- Session length equals the Okta ID token lifetime (one hour by default; configurable on the Okta authorization server). The module does not use refresh tokens.
- ID tokens larger than 3.9 KB (typically caused by a `groups` claim) do not fit in a cookie. The callback returns an explicit 500 in that case; remove the claim from the ID token in Okta.
- Removing the module: first remove the `lambda_function_association`, apply, wait until CloudFront has deleted the replicas (minutes to hours), then destroy the module. Deleting a replicated Lambda@Edge function earlier fails.

## Examples

- [complete](examples/complete): private S3 bucket, S3 origin access control, CloudFront distribution and this module, with outputs listing the URIs to register in Okta.

## Contributing

Issues and pull requests are welcome. The Lambda code has no npm dependencies; run the unit tests and Terraform tests before opening a PR:

```shell
node --test "lambda/test/*.test.mjs"
terraform init -backend=false && terraform test
```

### Pre-Commit

Installation: [install pre-commit](https://pre-commit.com/) and execute `pre-commit install`. This will generate pre-commit hooks according to the config in `.pre-commit-config.yaml`

Before submitting a PR be sure to have used the pre-commit hooks or run: `pre-commit run -a`

The `pre-commit` command will run:

- Terraform fmt
- Terraform validate
- Terraform docs
- Terraform validate with tflint
- check for merge conflicts
- fix end of files

as described in the `.pre-commit-config.yaml` file

## Versioning and Releases

This module follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`). Releases are automated with [semantic-release](https://github.com/semantic-release/semantic-release) and derived from [Conventional Commits](https://www.conventionalcommits.org/) on `main`:

| Commit type | Example | Version bump |
| ----------- | ------- | ------------ |
| `fix:` | `fix: reject tokens without kid` | PATCH (`x.y.Z`) |
| `feat:` | `feat: add logout path output` | MINOR (`x.Y.0`) |
| `feat!:` / `fix!:` or a `BREAKING CHANGE:` footer | `feat!: rename okta_issuer` | MAJOR (`X.0.0`) |

Guidelines for choosing the bump:

- **PATCH**: backwards-compatible bug fixes that do not change the module interface or default behaviour.
- **MINOR**: backwards-compatible new features (new variables, new optional resources) where existing configurations keep working unchanged.
- **MAJOR**: any backwards-incompatible change: removed or renamed variables/outputs, changed defaults that alter live infrastructure, or behaviour that requires consumers to take action before upgrading.

Always pin the module to a specific version so that MAJOR releases never reach your infrastructure unintentionally.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.10 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | >= 2.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_archive"></a> [archive](#provider\_archive) | >= 2.7 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_iam_role.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_function.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_ssm_parameter.client_secret](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [archive_file.this](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_name"></a> [name](#input\_name) | Name of the Lambda@Edge function, IAM role and SSM parameter prefix. | `string` | `"cloudfront-okta-auth"` | no |
| <a name="input_okta_client_id"></a> [okta\_client\_id](#input\_okta\_client\_id) | Client ID of the Okta OIDC web application. | `string` | n/a | yes |
| <a name="input_okta_client_secret"></a> [okta\_client\_secret](#input\_okta\_client\_secret) | Client secret of the Okta OIDC web application. Stored as an SSM SecureString parameter in us-east-1. | `string` | n/a | yes |
| <a name="input_okta_issuer"></a> [okta\_issuer](#input\_okta\_issuer) | Okta issuer URL without trailing slash: the org authorization server (https://acme.okta.com) or a custom authorization server (https://acme.okta.com/oauth2/default). | `string` | n/a | yes |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to all resources. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_callback_path"></a> [callback\_path](#output\_callback\_path) | Path that must be registered in Okta as sign-in redirect URI: https://<site-domain><callback\_path>. |
| <a name="output_lambda_function_arn"></a> [lambda\_function\_arn](#output\_lambda\_function\_arn) | Unversioned ARN of the Lambda@Edge function. |
| <a name="output_lambda_function_name"></a> [lambda\_function\_name](#output\_lambda\_function\_name) | Name of the Lambda@Edge function. |
| <a name="output_lambda_qualified_arn"></a> [lambda\_qualified\_arn](#output\_lambda\_qualified\_arn) | Versioned ARN of the Lambda@Edge function. Use it as lambda\_arn in a viewer-request lambda\_function\_association. |
| <a name="output_lambda_role_arn"></a> [lambda\_role\_arn](#output\_lambda\_role\_arn) | ARN of the Lambda@Edge execution role. |
| <a name="output_logout_path"></a> [logout\_path](#output\_logout\_path) | Path that clears the session and signs the user out of Okta. |
| <a name="output_okta_endpoints"></a> [okta\_endpoints](#output\_okta\_endpoints) | Okta endpoints derived from okta\_issuer. |
| <a name="output_ssm_parameter_arn"></a> [ssm\_parameter\_arn](#output\_ssm\_parameter\_arn) | ARN of the SSM SecureString parameter holding the Okta client secret. |
<!-- END_TF_DOCS -->

## Authors

Module is maintained by [Alfredo Gottardo](https://github.com/AlfGot), [David Beauvererd](https://github.com/Davidoutz), [Davide Cammarata](https://github.com/DCamma), [Francisco Ferreira](https://github.com/cferrera), [Roland Bapst](https://github.com/rbapst-tamedia) and [Samuel Wibrow](https://github.com/swibrow)

## License

Apache 2 Licensed. See [LICENSE](LICENSE) for full details.
