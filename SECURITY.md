# Security Policy

## Trust boundary

Cloudflare Access must be the only normal network path to protected WordPress administration endpoints. The plugin validates Access assertions at the WordPress layer, but it cannot secure a publicly reachable origin, code that runs before WordPress, or vulnerabilities in other components.

Use Cloudflare Tunnel or equivalent authenticated origin controls. Firewall rules based only on published Cloudflare IP ranges are weaker and must be maintained carefully.

## Authentication and authorization

The plugin accepts only RS256 Cloudflare Access application tokens for the configured team issuer and AUD tag. JWKS and identity URLs are derived from a validated `<team>.cloudflareaccess.com` hostname, fetched with WordPress safe HTTP functions, bounded responses, no redirects, and short timeouts. A missing `kid` triggers one JWKS refresh to support key rotation.

For every provisioning or role-sync decision, the plugin requires the `get-identity` email and `user_uuid` to match the signed token. Service-token identities are rejected. A successful lookup with no matching group revokes all roles and sessions. Network, HTTP, or JSON failure denies the request and never preserves access by pretending the old group assignment is current.

Managed accounts:

- are bound to the Cloudflare subject;
- cannot use native WordPress passwords;
- cannot reset native WordPress passwords;
- cannot use Application Passwords;
- have existing sessions and Application Passwords removed when linked, downgraded, or revoked;
- require an Access token for authenticated REST use.

Unmanaged accounts retain native WordPress behavior and are intended only for controlled break-glass recovery. Their origin path, credentials, MFA, and monitoring are deployment responsibilities.

The plugin is independent of the upstream IdP protocol. Cloudflare may authenticate against Entra ID, Okta, Google Workspace, generic OIDC, or generic SAML, but WordPress trusts only the normalized Cloudflare Access application JWT and identity endpoint. Every new IdP integration must be tested to confirm a verified email, stable Cloudflare subject, and expected group identifiers.

## Existing-account migration

Automatic email linking is disabled by default. If temporarily enabled, only a verified Cloudflare identity with an explicitly mapped group may bind an existing account. Email is used only for the initial lookup; subsequent access requires the stored subject.

Enable migration mode for the shortest possible window, verify the intended accounts, then disable it. A compromised IdP mailbox could otherwise claim a same-email WordPress account during that window.

## Operational requirements

- Protect `/wp-admin` and `/wp-login.php` with the same Access application.
- Review `admin-ajax.php`, `admin-post.php`, authenticated `/wp-json` routes, XML-RPC, custom front-end actions, and hosting control-panel shortcuts.
- Keep the Access application cookie available to browser REST calls if managed REST enforcement is enabled.
- Use MFA, short administrative sessions, and Cloudflare identity refresh after group changes.
- Keep WordPress, PHP, themes, plugins, and `firebase/php-jwt` updated.
- Leave the no-group fallback at `deny` unless Subscriber access is a deliberate requirement.
- Keep automatic existing-account linking disabled outside migration.
- Review WordPress Site Health, plugin security events, and Cloudflare Access logs.
- Test role removal, downgrade, IdP outage, JWKS rotation, logout, REST, and origin bypass before rollout.

## Lifecycle and session limitations

The plugin implements JIT provisioning and authorization-time role synchronization, not SCIM. Removing an identity from an IdP does not automatically delete the WordPress database row. For urgent offboarding, remove the user from the IdP group, revoke active Cloudflare Access sessions, and then remove or retain the local WordPress account according to content-retention requirements. Fleet deletion can be performed with MainWP, but the MainWP connection user must be migrated before deletion.

Cloudflare group state follows the Access identity session. Do not assume an IdP group edit is visible immediately in an already issued application token. Refresh or revoke the Access session when testing or enforcing a change.

WordPress logout, Cloudflare Access logout, and IdP logout are distinct operations. The default plugin logout ends WordPress and Cloudflare Access sessions but deliberately does not sign the user out of Microsoft 365 or other applications at the upstream IdP. An active IdP SSO session can authenticate the user again on the next visit.

## Secrets and privacy

Do not put API tokens, IdP secrets, SAML responses, JWTs, cookies, private keys, or personal data into plugin settings. The plugin does not persist these values and its security log intentionally excludes email addresses and credentials.

## Reporting

This project has not been independently audited. Report vulnerabilities with a private GitHub security advisory or directly to the repository owner. Do not publish exploit details before coordinated remediation.
