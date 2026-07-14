# Changelog

## 2.0.2 - 2026-07-14

- Accept Cloudflare JWT headers that omit the optional RFC 7519 `typ` field while continuing to require RS256, a bounded key ID, signature verification, Issuer, and Audience.
- Add granular, token-free diagnostic codes for JWT header encoding, JSON, algorithm, and key ID failures.
- Document the IdP-to-Cloudflare-to-WordPress trust model, OIDC/SAML portability, JIT lifecycle, logout semantics, manual deprovisioning, and fleet operation.
- Add a documentation-ready architecture infographic.

## 2.0.1 - 2026-07-14

- Record bounded, token-free diagnostic codes when an initial Cloudflare Access JWT is missing or rejected.
- Distinguish malformed headers, unavailable JWKS, signing-key, signature, time, issuer, audience, and identity-claim failures.
- Allow the already verified Access application JWT to authenticate the server-side identity lookup when the application cookie is not forwarded to PHP.

## 2.0.0 - 2026-07-14

- Make role synchronization fail closed and revoke roles, sessions, and Application Passwords after an authoritative no-group result.
- Bind managed accounts to the Cloudflare subject and reject email/subject mismatches and service identities.
- Disable native passwords and Application Passwords for managed users; enforce Access identity on managed REST requests.
- Add safe one-time upgrade binding for the already authenticated 1.x administrator and an explicit migration mode for other existing accounts.
- Restrict the team, issuer, JWKS, header, audience, fallback roles, redirects, HTTP responses, and configuration input.
- Refresh JWKS once for an unknown key ID and reduce cache lifetime.
- Make group-map deletion work and replace the complete map on fleet import.
- Add bounded security events, Site Health checks, CI, dependency updates, and unit tests.
- Require WordPress 6.5+, PHP 8.2+, and update bundled `firebase/php-jwt` to 7.1.0.
