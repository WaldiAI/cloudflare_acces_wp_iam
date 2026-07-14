# Cloudflare Configuration Guide

This guide shows how to configure Cloudflare DNS and Cloudflare Zero Trust Access for WordPress admin protection.

The target architecture is:

```text
User
  -> https://example.com/wp-admin
  -> Cloudflare Access
  -> Okta / Google Workspace / Microsoft Entra ID
  -> Cloudflare Access JWT
  -> WordPress
  -> Cloudflare Access WP IAM plugin
```

Cloudflare protects the WordPress admin entry points. WordPress does not integrate directly with SAML or OIDC. The WordPress plugin validates Cloudflare Access JWTs and maps identity provider groups to WordPress roles.

![Detailed Cloudflare Access WP IAM authentication and lifecycle architecture](docs/assets/cloudflare-access-wp-iam-architecture-v2.png)

See [ARCHITECTURE.md](ARCHITECTURE.md) for the trust boundaries, protocol-level sequence, JWT/JWKS validation, JIT provisioning, role synchronization, logout semantics, and lifecycle limitations.

## 1. Add The Domain To Cloudflare

Start in the main Cloudflare dashboard, not in Zero Trust.

Navigation:

```text
Cloudflare dashboard
-> Account home
-> Domains
-> Add a domain
```

Steps:

1. Enter the domain, for example:

   ```text
   example.com
   ```

2. Choose:

   ```text
   Full DNS setup
   ```

3. Select the Cloudflare plan.

   For a basic WordPress Access deployment, the Free plan is enough.

4. Cloudflare scans existing DNS records.

5. Review imported DNS records before changing nameservers.

Important records to verify:

```text
A / AAAA / CNAME records for the website
MX records for mail
TXT SPF records
TXT / CNAME DKIM records
TXT DMARC records
autodiscover records if Microsoft 365 or Google Workspace mail is used
```

If mail is hosted in Microsoft 365, Google Workspace, or another provider, keep those MX/SPF/DKIM/DMARC records exactly as required by that provider.

## 2. Update Nameservers At The Registrar

After Cloudflare imports DNS records, it shows two nameservers, for example:

```text
macy.ns.cloudflare.com
yevgen.ns.cloudflare.com
```

Go to your domain registrar, for example OVH, Namecheap, GoDaddy, or another provider.

Navigation example for OVH:

```text
OVH Panel
-> Domains
-> example.com
-> DNS servers / Nameservers
-> Change DNS servers
```

Replace the old registrar nameservers with the Cloudflare nameservers.

Before saving, check DNSSEC:

```text
If DNSSEC is enabled at the registrar, disable it before changing nameservers unless you also configure Cloudflare DNSSEC correctly.
```

Wait until Cloudflare shows the domain as active.

## 3. Configure DNS Records For WordPress

After the domain is active in Cloudflare:

Navigation:

```text
Cloudflare dashboard
-> Account home
-> Domains
-> example.com
-> DNS
-> Records
```

For the WordPress website, configure:

```text
Type: A
Name: @
IPv4 address: <hosting server IP>
Proxy status: Proxied
TTL: Auto
```

For `www`:

```text
Type: A or CNAME
Name: www
Target: <hosting server IP or example.com>
Proxy status: Proxied
TTL: Auto
```

Use `Proxied` for the hostname protected by Cloudflare Access.

Use `DNS only` for records that should not go through Cloudflare HTTP proxy, for example:

```text
mail
ftp
autodiscover
imap
smtp
pop
```

## 4. Configure SSL/TLS

Navigation:

```text
Cloudflare dashboard
-> Account home
-> Domains
-> example.com
-> SSL/TLS
-> Overview
```

Recommended setting:

```text
Full (strict)
```

Use `Full (strict)` when the origin hosting server has a valid certificate, for example Let's Encrypt.

Avoid `Flexible` for WordPress. It commonly causes redirect loops because Cloudflare connects to the origin over HTTP while WordPress expects HTTPS.

## 5. Open Cloudflare Zero Trust

Navigation:

```text
Cloudflare dashboard
-> Zero Trust
```

If this is the first setup:

1. Choose a team name.

   Example:

   ```text
   example-team
   ```

2. Your Cloudflare Access team domain will be:

   ```text
   example-team.cloudflareaccess.com
   ```

3. Choose the Free plan if it fits the team size and use case.

The team domain is later used in the WordPress plugin:

```text
Team domain:
example-team.cloudflareaccess.com

Issuer:
https://example-team.cloudflareaccess.com

JWKS URL:
https://example-team.cloudflareaccess.com/cdn-cgi/access/certs
```

## 6. Add An Identity Provider

Navigation:

```text
Zero Trust
-> Integrations
-> Identity providers
-> Add an identity provider
```

You can use:

```text
Azure AD
Google Workspace
Okta
SAML
OpenID Connect
```

For this WordPress plugin, the IdP type does not matter directly. Cloudflare authenticates the user and then sends a Cloudflare Access JWT to WordPress.

The plugin needs Cloudflare to provide:

```text
verified email
stable Cloudflare sub / user_uuid
groups / group names / group IDs / group emails
```

The plugin does not consume the IdP's SAML assertion or OIDC token directly. Cloudflare normalizes the upstream identity and issues the Access application JWT that WordPress validates.

## 7. Generic SAML Identity Provider

Use this for Google Workspace SAML, Okta SAML, or another SAML IdP.

Navigation:

```text
Zero Trust
-> Integrations
-> Identity providers
-> Add an identity provider
-> SAML
```

Recommended Cloudflare fields:

```text
Name:
Google Workspace SAML
or
Okta SAML

Single sign-on URL:
<IdP SSO URL from Google Workspace / Okta>

IdP Entity ID or Issuer URL:
<IdP issuer from Google Workspace / Okta>

Signing certificate:
<IdP X.509 certificate>

Email attribute name:
email

SAML attributes:
groups
first_name
last_name
```

Leave these off unless specifically required:

```text
Enable SCIM: Off
Sign SAML authentication request: Off
SAML header attributes: empty
```

The IdP must send a SAML assertion with attributes similar to:

```text
email       = user@example.com
first_name  = User
last_name   = Example
groups      = wp-admins
groups      = wp-editors
```

Use exact group values later in Cloudflare policies and in the WordPress plugin.

## 8. Google Workspace SAML Notes

In Google Admin Console, configure a custom SAML app.

Cloudflare callback URL:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/callback
```

Common Google SAML mappings:

```text
Primary email -> email
First name    -> first_name
Last name     -> last_name
```

Group membership:

```text
Google groups -> groups
```

Recommended group filter:

```text
^(wp-admins|wp-editors)$
```

or for all WordPress IAM groups:

```text
^wp-.*
```

If Google sends `wp-admins`, then Cloudflare policy and the WordPress plugin must also use:

```text
wp-admins
```

not:

```text
wp-admins@example.com
```

unless that is the exact value visible in the SAML assertion or Cloudflare identity debug.

## 9. Okta SAML Notes

In Okta, create a SAML 2.0 application.

Okta SAML settings:

```text
Single sign-on URL:
https://<team>.cloudflareaccess.com/cdn-cgi/access/callback

Audience URI / SP Entity ID:
https://<team>.cloudflareaccess.com/cdn-cgi/access/callback

Name ID format:
EmailAddress

Application username:
Email
```

Attribute statements:

```text
email      = user.email
first_name = user.firstName
last_name  = user.lastName
```

Group attribute statements:

```text
Name:
groups

Filter:
Matches regex

Value:
^(wp-admins|wp-editors)$
```

After creating the Okta app, copy these values into Cloudflare SAML IdP settings:

```text
Sign on URL
Issuer
Signing certificate
```

## 10. Microsoft Entra ID Notes

For Microsoft Entra ID, Cloudflare has a native Azure AD / Entra connector.

The connector uses OpenID Connect authentication on top of OAuth 2.0. Enable PKCE for the Authorization Code flow. Cloudflare can use delegated Microsoft Graph permissions to resolve the user's group membership.

Navigation:

```text
Zero Trust
-> Integrations
-> Identity providers
-> Add an identity provider
-> Azure AD
```

Typical values:

```text
Application ID:
<Entra App Registration client ID>

Application secret:
<Entra client secret value>

Directory ID:
<Entra tenant ID>

Support groups:
On

Proof Key for Code Exchange (PKCE):
On

Enable SCIM:
Off (the WordPress plugin does not require SCIM)
```

In Entra, the app registration redirect URI should be:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/callback
```

Register it as a **Web** redirect URI. In the Entra application overview, copy and label these values separately:

```text
Application (client) ID -> Cloudflare Application ID
Directory (tenant) ID   -> Cloudflare Directory ID
Object ID               -> inventory only; not the client ID
```

Create a client secret under **Certificates & secrets**. Copy the secret **Value** immediately; do not copy only its Secret ID. Store the value in a password manager and enter it only in the Cloudflare identity-provider form.

Under **API permissions**, add these Microsoft Graph **Delegated permissions**:

```text
email
offline_access
openid
profile
User.Read
Directory.Read.All
GroupMember.Read.All
```

Grant tenant-wide administrator consent for the permissions that require it. This is the permission set tested and supported by Cloudflare for the Entra group integration. More narrowly scoped permissions require separate validation.

If using Entra group IDs, Cloudflare policies and the WordPress plugin may need Object IDs such as:

```text
7dcf3b3f-b8a2-44c3-9937-b9c91ac6fc5e
```

This is the **group Object ID**, not the Entra application Object ID. Verify the exact group object returned by Cloudflare at `/cdn-cgi/access/get-identity` before finalizing the WordPress mapping.

## 11. Create A Cloudflare Access Application

Navigation:

```text
Zero Trust
-> Access controls
-> Applications
-> Create new application
-> Self-hosted and private
-> Public DNS
-> Continue with Self-hosted and private
```

Use `Public DNS` when the WordPress domain is public and proxied through Cloudflare DNS.

## 12. Configure Destinations

In the new self-hosted application, configure public hostnames.

For a root domain:

```text
Subdomain:
<empty>

Domain:
example.com

Path:
wp-admin
```

Add another public hostname:

```text
Subdomain:
<empty>

Domain:
example.com

Path:
wp-login.php
```

Cloudflare displays the slash separately. Enter:

```text
wp-admin
wp-login.php
```

not:

```text
/wp-admin
/wp-login.php
```

Common WordPress paths:

```text
Protect:
wp-admin
wp-login.php

Review and test as authenticated entry points:
wp-admin/admin-ajax.php
wp-admin/admin-post.php
wp-json
xmlrpc.php

Usually keep public or protect with a separate machine policy:
wp-cron.php
```

Do not blindly place the complete `wp-json` namespace behind an interactive login because WordPress and plugins may expose intentional public REST routes. The plugin rejects authenticated REST requests by managed users unless it can validate an Access application token. Browser REST calls can use the `CF_Authorization` application cookie even when Cloudflare does not add the Access header on that path. Leave the Access Cookie Path setting disabled (domain-wide) when Gutenberg or another admin UI calls `/wp-json`.

For WooCommerce, Elementor, forms, and front-end AJAX, test `admin-ajax.php` and `admin-post.php` routes individually. A custom endpoint that performs privileged work outside the standard WordPress routes must enforce equivalent authentication.

### Protect the origin

Path policies are not sufficient when the hosting origin is reachable directly. Prefer Cloudflare Tunnel so there is no public origin listener. Otherwise use authenticated origin pulls or carefully maintained firewall controls and verify that direct IP/alternate-host requests cannot reach WordPress administration. The plugin cannot repair an origin bypass before WordPress loads.

## 13. Create Access Policy

In the same application:

```text
Access policies
-> Builder
-> Create new policy
```

Policy details:

```text
Policy name:
Allow WordPress Admin Access

Action:
Allow

Policy session duration:
Same as application session duration
or
8 hours / 24 hours
```

For Google Workspace SAML or Okta SAML:

```text
Selector:
SAML Attribute

Attribute name:
groups

Value:
wp-admins
```

Add another Include OR for editors if they should access WordPress:

```text
Selector:
SAML Attribute

Attribute name:
groups

Value:
wp-editors
```

For Entra native groups:

```text
Selector:
Azure Groups

Value:
<Entra group Object ID>
```

Example:

```text
7dcf3b3f-b8a2-44c3-9937-b9c91ac6fc5e
```

Save the policy.

## 14. Configure Authentication For The Application

In the application configuration, find:

```text
Authentication
```

Recommended settings:

```text
Accept all available identity providers:
Off

Choose available identity providers:
Select only the IdP for this WordPress app

Apply instant authentication:
On if there is only one IdP and you want to skip the Cloudflare provider selection screen

Authenticate with Cloudflare One Client:
Off
```

If `Accept all available identity providers` is left on, users may see all configured IdPs or unwanted login methods such as One-time PIN.

## 15. Configure Application Details

In the application details section:

```text
Name:
example.com WordPress Admin

Session Duration:
8 hours or 24 hours
```

Recommended:

```text
8 hours
```

for production admin access.

Use `24 hours` for easier testing.

Save the application.

## 16. Find Values For The WordPress Plugin

After the Access application is created, open it in Cloudflare.

Values for the plugin:

```text
Team domain:
<team>.cloudflareaccess.com

JWKS URL:
https://<team>.cloudflareaccess.com/cdn-cgi/access/certs

JWT header:
Cf-Access-Jwt-Assertion

Issuer:
https://<team>.cloudflareaccess.com

Audience:
Cloudflare Access Application AUD tag
```

The Audience value is the application AUD tag. It is a long hash-like value generated by Cloudflare for the Access application.

Example:

```text
225e3c3d46aff0dc6cdf34f9b0ac4c0eee22624c80d557e67a2fbe2e82a03f17
```

## 17. Configure The WordPress Plugin

In WordPress:

```text
WordPress Admin
-> Settings
-> Cloudflare Access WP IAM
```

Cloudflare Access settings:

```text
Team domain:
<team>.cloudflareaccess.com

JWKS URL:
https://<team>.cloudflareaccess.com/cdn-cgi/access/certs

JWT header:
Cf-Access-Jwt-Assertion

Issuer:
https://<team>.cloudflareaccess.com

Audience:
<Cloudflare Access AUD tag>

No mapped group:
Deny access and remove managed roles

Existing WordPress accounts:
Do not link automatically

Managed REST access:
Enabled
```

The plugin derives JWKS URL, issuer, and JWT header from the validated team domain. These fields are read-only to prevent arbitrary outbound identity or key requests.

Group to role mapping:

```text
Administrator:
wp-admins

Editor:
wp-editors
```

Use one group value per line. Use the exact values returned by Cloudflare identity context.

The default production-safe settings are:

```text
No mapped group:          Deny access and remove managed roles
Existing WP accounts:    Do not link automatically
Managed REST access:     Enabled
Logout mode:             Cloudflare logout through the application domain
```

After saving, check **Tools -> Site Health**. The plugin reports incomplete Cloudflare settings, missing role mappings, enabled account-linking mode, a pending version 1.x migration link, and disabled managed REST enforcement.

For an upgrade from version 1.x, existing users do not yet have a Cloudflare subject binding. Version 2 allows one bootstrap link only when an already authenticated WordPress session matches the verified Cloudflare email and an explicit mapped group; this prevents the upgrading administrator from being locked out and consumes the bootstrap flag. Then temporarily enable one-time verified email linking only after checking exact emails and mappings, let other intended users sign in once, and disable linking again. Linking removes existing WordPress sessions and Application Passwords. Keep a separate unmanaged break-glass administrator outside this migration.

## 18. Test The Flow

Use a private/incognito browser window.

Open:

```text
https://example.com/wp-admin
```

Expected flow:

```text
WordPress admin URL
-> Cloudflare Access
-> selected IdP
-> MFA if required by IdP
-> Cloudflare policy evaluation
-> WordPress
-> plugin validates JWT
-> JIT user creation or update
-> WordPress admin access with mapped role
```

Run the following acceptance tests before production rollout:

1. A new user in a mapped group is created with exactly the expected role.
2. A user with no mapped group is denied and is not created.
3. An existing local account is not linked while linking mode is disabled.
4. A controlled existing-account migration binds the expected email once, destroys old sessions and Application Passwords, and works after linking mode is disabled again.
5. Moving a managed user to a lower mapped group updates the role and invalidates old WordPress sessions.
6. Removing all mapped groups, followed by Cloudflare identity refresh/session revocation, removes managed roles and denies access.
7. WordPress logout ends the WordPress and Cloudflare Access sessions, while an active IdP session can still perform SSO on the next visit.
8. The unmanaged break-glass administrator still works through its deliberately protected recovery path.

## 19. Debug Cloudflare Access

Cloudflare Access logs:

```text
Zero Trust
-> Insights & Logs
-> Logs
-> Access authentication logs
```

Use this when:

```text
User is denied by Cloudflare
Wrong group is matched
Policy does not allow the user
Wrong IdP is used
```

For SAML debugging:

```text
Use SAML-tracer browser extension
Check SAML Response
Verify attributes:
email
groups
first_name
last_name
```

SAML-tracer is useful only when the IdP-to-Cloudflare connection uses SAML. The native Microsoft Entra connector uses OIDC/OAuth 2.0, so diagnose it with Cloudflare Access logs, the Cloudflare identity test, browser network redirects, and the `get-identity` response instead of looking for a SAML assertion.

The most important value to verify is the group attribute. Do not assume that the group value in Cloudflare or WordPress should be the same as the display name visible in the IdP admin console.

Common differences:

```text
Microsoft Entra ID:
May send group Object IDs, for example:
7dcf3b3f-b8a2-44c3-9937-b9c91ac6fc5e

Okta:
Often sends group names, for example:
wp-admins
wp-editors

Google Workspace SAML:
May send group names or email-style values depending on SAML app configuration, for example:
wp-admins
wp-admins@example.com
```

Recommended validation workflow:

```text
1. Reproduce the login with SAML-tracer enabled.
2. Open the SAML Response.
3. Find the AttributeStatement.
4. Check the exact values under the groups attribute.
5. Use those exact values in Cloudflare Access policies.
6. Use those exact values in the WordPress plugin group-to-role mapping.
7. Retest with a clean private/incognito session.
```

If the assertion sends:

```text
groups = wp-admins
```

then use:

```text
wp-admins
```

If the assertion sends:

```text
groups = wp-admins@example.com
```

then use:

```text
wp-admins@example.com
```

If Entra sends:

```text
groups = 7dcf3b3f-b8a2-44c3-9937-b9c91ac6fc5e
```

then use that Object ID.

For WordPress/plugin debugging:

```text
Check whether WordPress receives:
Cf-Access-Jwt-Assertion

Check Cloudflare get-identity response:
https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity

Check WordPress:
Settings -> Cloudflare Access WP IAM -> Recent IAM security events
```

Important distinction:

```text
JWT may not contain groups directly.
Cloudflare get-identity usually contains groups.
The plugin uses JWT for signed identity proof and get-identity for group context.
```

After an IdP group change, refresh the Cloudflare identity before retesting:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/refresh-identity
```

A confirmed identity response with no mapped group revokes the managed WordPress role and all sessions. A Cloudflare timeout or malformed response denies the request but is logged as an availability failure, not as an authoritative group removal.

The plugin security log stores only bounded metadata. It does not store JWTs, cookies, email addresses, SAML assertions, client secrets, or API tokens. Useful diagnostic events include:

```text
access_token_rejected
identity_lookup_failed
access_denied_no_mapped_group
jit_user_created
user_bound_to_cloudflare
role_changed
managed_access_revoked
wordpress_cloudflare_identity_mismatch
```

For `access_token_rejected`, the `error` detail distinguishes missing headers/cookies, invalid JWT shape or header encoding, wrong algorithm or key ID, unavailable JWKS, invalid signature, invalid time window, wrong issuer, wrong audience, and incomplete identity claims. These codes intentionally never contain the token value.

## 20. Common Problems

### User logs in but Cloudflare says access denied

Cause:

```text
Cloudflare policy does not match the user's group attribute.
```

Check:

```text
Access authentication logs
SAML assertion groups attribute
Cloudflare policy selector and value
```

### User reaches WordPress login instead of being auto-created

Possible causes:

```text
WordPress plugin is inactive
Wrong Audience value
Wrong Issuer value
Wrong JWKS URL
Cloudflare Access is not protecting the path
JWT header is not reaching WordPress/PHP
Cloudflare identity email or subject does not match the signed JWT
The identity has no group mapped to a WordPress role
```

If Cloudflare logs show **Allowed**, the IdP and edge policy succeeded. Continue diagnosis in the plugin's **Recent IAM security events**. An Access `Allowed` result does not prove that WordPress accepted the application JWT or found a role mapping.

### User is signed in again after WordPress logout

This is expected when the upstream IdP session is still active. The default plugin logout ends the current WordPress session and redirects through the application-domain Cloudflare Access logout endpoint. It does not sign the user out of Entra ID, Microsoft 365, Okta, Google Workspace, or other IdP applications.

On the next `/wp-admin` visit, Cloudflare starts authentication again and the IdP may complete SSO without prompting for a password. To revoke access rather than merely log out, remove the user from the authorized IdP group and revoke the active Cloudflare Access session.

### WordPress upload or forms show stale nonce

Possible cause:

```text
Session/cookie conflict during SSO testing.
```

Fix:

```text
Use the current plugin version.
Test in a clean private/incognito session.
Logout from Cloudflare Access when switching identities.
```

Cloudflare Access logout URL:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/logout
```

### Website has redirect loop

Likely cause:

```text
Cloudflare SSL/TLS mode is Flexible.
```

Fix:

```text
Set SSL/TLS mode to Full or Full (strict).
```

## 21. Scaling To Many WordPress Sites

For multiple WordPress publishing platforms:

```text
One Cloudflare Zero Trust account
One or more Identity Providers
Multiple Access applications
Each Access application protects up to the Cloudflare destination limit
Same WordPress plugin configuration model across sites
MainWP or scripts can apply plugin settings at scale
```

Cloudflare limits can change, so verify the current Access application and destination limits in Cloudflare documentation before designing a large fleet.

The plugin provides JIT provisioning and access revocation, not SCIM deletion. For manual offboarding across a fleet:

1. Remove the user from the WordPress access group in the IdP.
2. Revoke the user's active Cloudflare Access session.
3. Search for the email across child sites in MainWP.
4. Remove the account or role according to retention policy and reassign authored content when required.
5. Do not delete the MainWP connection user until the child site is connected with another administrator.

This workflow deliberately separates immediate access revocation from destructive deletion of content ownership.

## References

- Cloudflare DNS full setup and nameservers: https://developers.cloudflare.com/learning-paths/get-started/add-domain-to-cf/update-nameservers/
- Cloudflare Access application types: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/choose-application-type/
- Cloudflare generic SAML identity provider: https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-saml/
- Cloudflare Access application token and get-identity: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/
- Cloudflare Access JWT validation: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
- Cloudflare authorization cookie settings: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/
- Cloudflare Microsoft Entra ID integration: https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/entra-id/
- Cloudflare Access session management: https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/
- Cloudflare account limits: https://developers.cloudflare.com/cloudflare-one/account-limits/
- MainWP user management: https://docs.mainwp.com/sites/users/manage-users
