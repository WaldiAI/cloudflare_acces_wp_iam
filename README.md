# Cloudflare Access WP IAM

Cloudflare Access WP IAM is a WordPress IAM/SSO gateway that uses Cloudflare Access as the policy enforcement layer for WordPress admin panels.

The plugin does not integrate WordPress directly with SAML or OIDC. Instead, Okta, Google Workspace, Microsoft Entra ID, or another identity provider authenticates the user through Cloudflare Access. WordPress receives and validates Cloudflare's signed Access JWT, then creates or updates the local WordPress user just-in-time.

This makes the WordPress side IdP-agnostic: the same plugin can be used with Okta SAML, Google Workspace SAML, Microsoft Entra ID, generic SAML, or generic OIDC as long as Cloudflare Access provides a verified identity and group context.

## What This Project Demonstrates

- Zero Trust access control for WordPress admin panels
- Cloudflare Access as an IAM gateway and policy enforcement point
- IdP-agnostic SSO through Okta, Google Workspace, Microsoft Entra ID, or other Cloudflare Access IdPs
- JWT validation using Cloudflare JWKS
- issuer and audience validation
- just-in-time WordPress user provisioning
- IdP group-to-WordPress role mapping
- centralized logout integration with Cloudflare Access
- fleet configuration import for MainWP-style automation
- secure handling of identity data without storing tokens or secrets

## Architecture

```text
User
  ↓
Cloudflare Access protected /wp-admin
  ↓
Okta / Google Workspace / Entra ID / other IdP
  ↓
Cloudflare Access policy
  ↓
Cloudflare signed Access JWT
  ↓
WordPress plugin
  ↓
JIT user creation + group-to-role mapping
```

Cloudflare Access is the trust boundary. The IdP authenticates the user, Cloudflare enforces access policy, and WordPress validates Cloudflare's assertion.

## Important Detail: Groups

Cloudflare Access JWTs may not include group membership directly in the JWT payload. The plugin therefore uses:

```text
Cf-Access-Jwt-Assertion
```

for signed identity proof, and:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity
```

for group context.

The plugin can match groups by:

- group ID
- group name
- group email

Examples:

```text
wp-admins
wp-editors
7dcf3b3f-b8a2-44c3-9937-b9c91ac6fc5e
wp-admins@example.com
```

Use the exact group values Cloudflare returns in `get-identity`.

## WordPress Configuration

Configure the plugin under:

```text
Settings → Cloudflare Access WP IAM
```

Required values:

```text
Team domain:
your-team.cloudflareaccess.com

JWKS URL:
https://your-team.cloudflareaccess.com/cdn-cgi/access/certs

JWT Header:
Cf-Access-Jwt-Assertion

Issuer:
https://your-team.cloudflareaccess.com

Audience:
Cloudflare Access Application AUD tag
```

Then map IdP groups to WordPress roles:

```text
wp-admins  → administrator
wp-editors → editor
```

Group identifiers are stored as plain configuration values. They are not secrets. Do not store API tokens, client secrets, SAML responses, JWTs, or cookies in this plugin.

## Installation

For WordPress installation, use the packaged ZIP from the GitHub Releases page. The release ZIP should include the PHP dependency files required for JWT validation.

For source development:

```bash
composer install --no-dev
```

Then package the plugin directory as a WordPress-installable ZIP.

## Fleet Automation

The plugin includes an automation-friendly configuration path for agencies or teams managing multiple WordPress installations.

You can paste a JSON configuration in:

```text
Settings → Cloudflare Access WP IAM → Fleet config import
```

Example:

```json
{
  "team_domain": "your-team.cloudflareaccess.com",
  "jwks_url": "https://your-team.cloudflareaccess.com/cdn-cgi/access/certs",
  "jwt_header": "Cf-Access-Jwt-Assertion",
  "issuer": "https://your-team.cloudflareaccess.com",
  "audience": "Cloudflare Access AUD tag",
  "fallback_role": "subscriber",
  "logout_mode": "app",
  "groups": {
    "administrator": ["wp-admins"],
    "editor": ["wp-editors"]
  }
}
```

The same configuration can be applied through MainWP Code Snippets:

```php
cfawpiam_apply_config([
    'team_domain' => 'your-team.cloudflareaccess.com',
    'jwks_url' => 'https://your-team.cloudflareaccess.com/cdn-cgi/access/certs',
    'jwt_header' => 'Cf-Access-Jwt-Assertion',
    'issuer' => 'https://your-team.cloudflareaccess.com',
    'audience' => 'Cloudflare Access AUD tag',
    'fallback_role' => 'subscriber',
    'logout_mode' => 'app',
    'groups' => [
        'administrator' => ['wp-admins'],
        'editor' => ['wp-editors'],
    ],
]);
```

The plugin stores group identifiers as visible configuration after import. It does not store IdP secrets, SAML responses, Cloudflare JWTs, Cloudflare cookies, or API tokens.

## Cloudflare Access Configuration

Protect these paths:

```text
/wp-admin
/wp-login.php
```

The Access policy should allow groups that are allowed to access WordPress.

## Security Notes

This project is a security-focused portfolio implementation. It has not been independently audited.

The plugin does not store:

- IdP passwords
- SAML responses
- OIDC tokens
- Cloudflare JWTs
- Cloudflare cookies
- API tokens
- client secrets
- private keys

The plugin validates:

- Cloudflare Access JWT signature through JWKS
- issuer
- audience
- email claim

Classic WordPress login is intentionally not blocked by this plugin. If Cloudflare Access is disabled, WordPress can still be accessed using native WordPress credentials.

Recommended production hardening:

- protect the WordPress origin so `/wp-admin` cannot be bypassed outside Cloudflare
- restrict WordPress administrator accounts
- remove any debug endpoints after testing
- monitor Cloudflare Access authentication logs
- keep WordPress, plugins, and PHP dependencies updated
- use MFA and conditional access policies at the IdP layer

## Why Cloudflare Instead of Direct SAML to WordPress?

For one WordPress installation, direct SAML can be acceptable. For many separate WordPress sites, direct SAML creates repetitive ACS URL, Entity ID, certificate, and role mapping work.

This design keeps the IdP integration in Cloudflare and reuses the same WordPress plugin across many sites.

## License

This project is licensed under GPL-2.0-or-later.

See:

```text
LICENSE
THIRD_PARTY_NOTICES.md
SECURITY.md
```
