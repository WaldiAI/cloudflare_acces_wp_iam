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
email
groups / group names / group IDs / group emails
```

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

Enable SCIM:
Off for this basic setup
```

In Entra, the app registration redirect URI should be:

```text
https://<team>.cloudflareaccess.com/cdn-cgi/access/callback
```

If using Entra group IDs, Cloudflare policies and the WordPress plugin may need Object IDs such as:

```text
7dcf3b3f-b8a2-44c3-9937-b9c91ac6fc5e
```

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

Usually do not protect directly:
wp-admin/admin-ajax.php
wp-admin/admin-post.php
wp-cron.php
wp-json
```

For simple lab or controlled deployments, protecting `wp-admin` and `wp-login.php` is enough. For production WooCommerce, Elementor, forms, or frontend AJAX usage, test `admin-ajax.php` carefully before blocking it.

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

Fallback role:
Subscriber
```

Group to role mapping:

```text
Administrator:
wp-admins

Editor:
wp-editors
```

Use one group value per line. Use the exact values returned by Cloudflare identity context.

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
https://<domain>/cdn-cgi/access/get-identity
```

Important distinction:

```text
JWT may not contain groups directly.
Cloudflare get-identity usually contains groups.
The plugin uses JWT for signed identity proof and get-identity for group context.
```

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
```

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

## References

- Cloudflare DNS full setup and nameservers: https://developers.cloudflare.com/learning-paths/get-started/add-domain-to-cf/update-nameservers
- Cloudflare Access application types: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/choose-application-type/
- Cloudflare generic SAML identity provider: https://developers.cloudflare.com/cloudflare-one/identity/idp-integration/generic-saml/
- Cloudflare Access JWT validation: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
- Cloudflare account limits: https://developers.cloudflare.com/cloudflare-one/account-limits/
