# Architecture and IAM Flow

Cloudflare Access WP IAM separates authentication, edge authorization, and WordPress authorization. The identity provider remains the source of identity and group membership, Cloudflare Access is the identity-aware reverse proxy and policy enforcement point, and the plugin is the relying application that validates Cloudflare assertions and maps identity groups to local WordPress roles.

![Detailed Cloudflare Access WP IAM authentication and lifecycle architecture](docs/assets/cloudflare-access-wp-iam-architecture-v2.png)

## Responsibility model

| Component | IAM responsibility | Protocols and artifacts |
| --- | --- | --- |
| Microsoft Entra ID, Okta, Google Workspace, or another IdP | Authenticate the user, enforce password/MFA/Conditional Access controls, and maintain group membership | OIDC/OAuth 2.0 or SAML 2.0 over HTTPS |
| Cloudflare Access | Act as the identity-aware proxy, evaluate Zero Trust policy, maintain Access sessions, and issue an application-scoped identity assertion | Access policy, `CF_Authorization` cookies, RS256 JWT |
| Cloudflare Access WP IAM | Validate the Cloudflare assertion, obtain authoritative Cloudflare identity context, perform JIT provisioning, and map groups to one WordPress role | `Cf-Access-Jwt-Assertion`, JWKS, `get-identity`, WordPress authentication cookies |
| MainWP or another fleet tool | Perform operational user inventory and manual deletion across sites when SCIM is not used | WordPress/MainWP administration or API |

The WordPress site never receives the user's IdP password, the Entra client secret, a SAML assertion, or the IdP's raw OIDC tokens. It trusts only a valid, application-scoped assertion signed by the configured Cloudflare Access account.

## Interactive login sequence

1. The browser requests `https://example.com/wp-admin` or `https://example.com/wp-login.php` over HTTPS.
2. Cloudflare Access checks for a valid application session before the request reaches the WordPress origin.
3. If authentication is required, Access redirects the browser to the selected identity provider.
4. The IdP authenticates the user and applies its own MFA and conditional-access controls.
5. Cloudflare receives the authentication result through OIDC or SAML, resolves the identity and groups, and evaluates the Access policy.
6. If the policy allows the request, Cloudflare issues a global Access session and an application token scoped to the Access application AUD tag.
7. Cloudflare proxies the request and supplies the application JWT in `Cf-Access-Jwt-Assertion`. Browser traffic also uses the `CF_Authorization` application cookie.
8. The plugin validates the JWT signature and claims, then calls the Cloudflare `get-identity` endpoint to obtain the full group context.
9. The plugin maps an exact Cloudflare group ID, name, or email to a WordPress role.
10. The plugin creates a managed user just in time or synchronizes the existing managed user's role, then establishes the normal WordPress session.

The browser therefore has three separate session layers:

- the IdP session;
- the Cloudflare Access session;
- the WordPress session.

These sessions have different owners and lifetimes.

## Current Microsoft Entra ID path

The native Cloudflare Entra connector uses OpenID Connect for authentication on top of OAuth 2.0. The recommended login flow is Authorization Code with PKCE. Cloudflare uses the registered client ID, tenant ID, and client-secret value; the callback is:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/callback
```

When **Support groups** is enabled, the supported Cloudflare configuration uses delegated Microsoft Graph permissions:

```text
email
offline_access
openid
profile
User.Read
Directory.Read.All
GroupMember.Read.All
```

The permissions that require administrator consent must be granted for the tenant. The Entra application secret and Graph tokens belong only to the Cloudflare-to-Entra integration and must never be copied to WordPress.

## IdP portability

The boundary between the IdP and Cloudflare can change without changing the WordPress trust model:

```text
Entra ID -------- OIDC/OAuth 2.0 ----\
Okta ------------ OIDC or SAML ------- Cloudflare Access -- Access JWT --> WordPress
Google Workspace  OIDC or SAML -------/
```

The plugin is IdP-agnostic because it consumes the normalized Cloudflare identity, not an Entra-, Okta-, or Google-specific token. A new IdP deployment must still be tested for these required values:

- a verified email;
- a stable Cloudflare subject/user UUID;
- group context returned by Cloudflare;
- an exact group identifier that can be mapped to a WordPress role.

Depending on the IdP, a group may appear as an object ID, display name, or email address. The plugin accepts Cloudflare group string values and object forms containing `id`, `name`, or `email`, and compares them case-insensitively.

## Cloudflare application token validation

Cloudflare signs the application token with RS256. The plugin does not trust the presence of a header alone. It:

1. accepts only a bounded three-part JWT from the fixed `Cf-Access-Jwt-Assertion` header or the browser's `CF_Authorization` application cookie;
2. requires `alg=RS256` and a bounded signing key ID;
3. obtains signing keys from the derived endpoint `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`;
4. refreshes JWKS once when a previously unknown key ID appears;
5. verifies the cryptographic signature;
6. requires the configured Cloudflare issuer and application AUD tag;
7. requires an Access application token (`type=app`), valid time claims, email, subject, and identity nonce;
8. rejects expired, not-yet-valid, malformed, wrong-issuer, and wrong-audience tokens.

The plugin then calls:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity
```

The returned email must match the signed JWT email, and `user_uuid` must match the signed `sub`. Service-token identities cannot provision human WordPress accounts.

This creates two verification layers:

- Cloudflare blocks users who fail the edge policy;
- WordPress independently rejects requests that do not carry a valid assertion for this exact Cloudflare account and Access application.

## JIT provisioning and account binding

A new WordPress account is created only after token validation, identity lookup, and role mapping all succeed. The generated account:

- receives one mapped WordPress role;
- receives a random, unusable local password;
- is marked as Cloudflare-managed;
- is permanently bound to the Cloudflare `sub`/`user_uuid`.

Binding by subject prevents a later identity from claiming the account only because it presents the same email address. Existing accounts are not linked by default. The temporary one-time verified email-linking mode is intended only for a controlled migration, after which it must be returned to **Do not link automatically**.

Managed users cannot authenticate with a native WordPress password, reset that password, or use WordPress Application Passwords. Keep a separate, strongly protected unmanaged break-glass administrator.

## Group-to-role authorization

Cloudflare Access policy and WordPress role mapping are separate authorization decisions:

- the Access policy decides whether the identity can reach WordPress administration;
- the plugin decides which WordPress capabilities the identity receives.

When several configured groups match, the highest supported role wins:

```text
administrator > editor > author > contributor > subscriber
```

The secure no-match behavior is `deny`. After an authoritative identity lookup reports no mapped group, the plugin removes all roles from the managed account, destroys its WordPress sessions, removes Application Passwords, and denies the request. An identity endpoint timeout or malformed response also denies the current request, but is recorded as an availability/validation failure rather than treated as proof that the user left a group.

Cloudflare group information follows the Access identity session. Group removal is not a real-time SCIM push. For urgent revocation, remove the user from the IdP group and revoke the Cloudflare Access session instead of waiting for normal session expiry.

## Provisioning and deprovisioning scope

The plugin provides JIT provisioning and access revocation, but it is not a SCIM server:

| Lifecycle event | Current behavior |
| --- | --- |
| First authorized login | Create and bind a managed WordPress account |
| Mapped group changes | Synchronize the single WordPress role when refreshed Cloudflare identity is observed |
| No mapped group | Remove roles, sessions, and Application Passwords; deny access |
| User removed from IdP | Cloudflare access must be revoked/refreshed; the local database row remains |
| Delete WordPress account | Perform manually or in bulk with MainWP, with content reassignment as required |

This is a deliberate distinction between disabling access and deleting content ownership. If full automated account deletion is required later, add a separately authenticated lifecycle API or SCIM service with explicit safeguards; do not make the interactive login path delete user records.

## Logout semantics

With the default `app` logout mode, the WordPress logout action ends the current WordPress session and redirects to:

```text
https://<application-domain>/cdn-cgi/access/logout
```

This ends the current Cloudflare Access session but does not sign the user out of Entra ID, Okta, Google Workspace, Microsoft 365, or other IdP applications. On the next visit, an active IdP session may authenticate the user again without prompting for a password. This is normal SSO behavior.

The three plugin logout modes are:

- `app`: Cloudflare logout through the application domain;
- `team`: Cloudflare logout through the validated team domain;
- `disabled`: WordPress logout only.

Logout is not an administrative revocation mechanism. Offboarding must remove group access and revoke active Cloudflare sessions.

## Origin and trust boundary

The Access application must protect both `/wp-admin` and `/wp-login.php`, and deployments must review authenticated REST, AJAX, XML-RPC, and custom privileged endpoints. The Cloudflare proxy is part of the security boundary.

Prevent direct origin access with Cloudflare Tunnel or equivalent authenticated origin controls. A path policy alone cannot protect an origin that is reachable through its IP address, an alternate hostname, or another unprotected route. The plugin also cannot stop vulnerable code that executes before WordPress loads it.

## Fleet model

The benefit of this design is a stable application-side trust contract:

```text
One IdP integration with Cloudflare
        +
Cloudflare Access applications for protected WordPress destinations
        +
The same JWT-validation plugin and role-map format on every site
        +
MainWP or deployment automation for fleet configuration and manual lifecycle cleanup
```

Each Access application has its own AUD tag, so each WordPress deployment must use the AUD value of the application that protects it. Other settings and role-map conventions can be deployed centrally.

## References

- [Cloudflare Access application tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)
- [Cloudflare Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Cloudflare Access session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/)
- [Cloudflare Microsoft Entra ID integration](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/entra-id/)
- [MainWP user management](https://docs.mainwp.com/sites/users/manage-users)
