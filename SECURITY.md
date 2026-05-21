# Security Policy

## Security Model

Cloudflare Access WP IAM assumes that Cloudflare Access is the policy enforcement point in front of protected WordPress paths such as:

```text
/wp-admin
/wp-login.php
```

The plugin trusts only Cloudflare Access JWTs that pass:

- JWKS signature validation
- issuer validation
- audience validation
- email claim validation

The plugin then calls Cloudflare Access `get-identity` to retrieve group context for role mapping.

## Secrets

Do not store secrets in plugin configuration.

The plugin configuration is intended to contain only non-secret values:

- Cloudflare Access team domain
- JWKS URL
- JWT header name
- issuer
- audience
- group names, group IDs, or group emails
- fallback role
- logout mode

Do not paste these values into the plugin:

- Cloudflare API tokens
- Okta API tokens
- Google API tokens
- Microsoft Graph tokens
- client secrets
- private keys
- SAML responses
- JWTs
- Cloudflare cookies

## Known Security Boundary

Classic WordPress login is intentionally not blocked by this plugin. If Cloudflare Access is disabled or bypassed, WordPress native credentials may still work.

For production deployments, restrict direct origin access so protected WordPress paths cannot be reached outside Cloudflare.

## Recommended Hardening

- Require MFA at the identity provider layer.
- Use Cloudflare Access policies for `/wp-admin` and `/wp-login.php`.
- Validate the correct Cloudflare Access AUD tag per Access application.
- Remove temporary debug files after testing.
- Keep WordPress, themes, plugins, PHP, and dependencies updated.
- Restrict administrator accounts and review role mappings.
- Monitor Cloudflare Access authentication logs.

## Reporting Security Issues

This is a portfolio/lab project and is not independently audited.

If you find a security issue, open a private advisory or contact the repository owner directly. Do not publish exploit details before the maintainer has had time to review and respond.
