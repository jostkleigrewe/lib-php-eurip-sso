# Security Features

This document covers the security features of the EURIP SSO Bundle.

## HTTPS Enforcement

The bundle enforces HTTPS for all OIDC endpoints by default. This prevents:
- Man-in-the-middle attacks on token exchange
- Credential theft via network sniffing
- Token interception

### Configuration

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: 'https://sso.example.com'  # Must be HTTPS
    # requireHttps is true by default
```

### Allowed Development URLs

For local development, certain URLs are exempt from HTTPS requirement:
- `http://localhost`
- `http://127.0.0.1`
- `http://[::1]`
- `http://host.docker.internal`

### Disabling HTTPS Check (Development Only)

```php
// Only for local development!
$client = OidcClientFactory::create(
    issuer: 'http://sso-dev.local:8080',
    // ...
    requireHttps: false,  // Disables HTTPS enforcement
);
```

**Warning:** Never disable `requireHttps` in production. The `InsecureUrlException` is thrown for non-HTTPS URLs to protect your application.

### Validated Endpoints

HTTPS is enforced for critical server-to-server endpoints:
- `issuer` - The OIDC provider URL
- `token_endpoint` - Token exchange endpoint
- `jwks_uri` - JSON Web Key Set endpoint
- `userinfo_endpoint` - User info endpoint

---

## JWT Signature Verification

All ID tokens are cryptographically verified using the provider's public keys.

### How It Works

1. **JWKS Fetching** - Public keys are fetched from the provider's `jwks_uri`
2. **Key Matching** - The `kid` (Key ID) in the JWT header is matched to a public key
3. **RS256 Verification** - The signature is verified using RSA-SHA256
4. **Key Rotation Resilience** - If verification fails, keys are refreshed and verification is retried

### Configuration

```yaml
eurip_sso:
    authenticator:
        verify_signature: true  # Default: true (recommended!)
```

### JwtVerifier Class

The `JwtVerifier` class handles all signature verification:

```php
use Jostkleigrewe\Sso\Client\JwtVerifier;

$verifier = new JwtVerifier(
    jwksUri: 'https://sso.example.com/.well-known/jwks.json',
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    logger: $logger,
    cache: $cache,
    cacheKey: 'my_app.jwks',
    cacheTtl: 600,  // 10 minutes
);

// Verify a token
$isValid = $verifier->verifySignature($idToken);
```

### JWKS Caching

JWKS are cached to reduce latency and network calls:
- **Default TTL:** 10 minutes
- **Cache Key:** `eurip_sso.jwks.v1.<hash>`
- **Auto-Refresh:** Keys are refreshed on cache miss or verification failure

```bash
# Warm up cache (e.g., during deployment)
bin/console eurip:sso:cache-warmup
```

---

## PKCE (Proof Key for Code Exchange)

The bundle uses PKCE with S256 challenge method to prevent authorization code interception.

### How PKCE Works

1. **Code Verifier** - Random 43-128 character string generated for each login
2. **Code Challenge** - SHA256 hash of the verifier, sent with authorization request
3. **Token Exchange** - Original verifier sent with token request for verification

```
Login Request → code_challenge = SHA256(code_verifier)
                code_challenge_method = S256

Callback      → code_verifier (original value)
                ↓
Provider verifies: SHA256(code_verifier) == code_challenge
```

### Why PKCE Matters

Without PKCE, an attacker who intercepts the authorization code could exchange it for tokens. With PKCE, the attacker would also need the `code_verifier`, which never leaves your server.

---

## State Parameter (CSRF Protection)

The `state` parameter prevents Cross-Site Request Forgery attacks on the callback endpoint.

### How It Works

1. **Generation** - Cryptographically secure random string
2. **Storage** - Stored in server-side session before redirect
3. **Validation** - Timing-safe comparison on callback

```php
// Validation uses hash_equals() to prevent timing attacks
if (!hash_equals($storedState, $receivedState)) {
    throw new InvalidStateException();
}
```

### Common Issues

- **Session Not Persisted** - State stored but not available on callback
- **Load Balancer** - Different server handles callback
- **Cookie Issues** - SameSite policy prevents cookie

See [Troubleshooting](TROUBLESHOOTING.md#1-invalid-state-nach-login) for solutions.

---

## Nonce Validation

The `nonce` parameter prevents token replay attacks.

### How It Works

1. **Generation** - Random string included in authorization request
2. **Storage** - Stored in session
3. **Verification** - Must match `nonce` claim in ID token

```php
// ID token must contain matching nonce
$claims = $client->decodeIdToken($idToken);
if ($claims['nonce'] !== $sessionNonce) {
    throw new ClaimsValidationException('Nonce mismatch');
}
```

---

## Claims Validation

ID token claims are validated according to OIDC specification:

| Claim | Validation |
|-------|------------|
| `iss` | Must match configured issuer |
| `aud` | Must include client ID |
| `exp` | Must not be expired |
| `iat` | Must not be in the future |
| `nonce` | Must match session nonce |

---

## Open Redirect Protection

The bundle validates return URLs to prevent open redirect attacks.

### Blocked Patterns

- Protocol-relative URLs: `//evil.com`
- Absolute URLs to other domains: `https://evil.com`
- URLs with newlines (header injection): `http://app.com\nLocation: evil.com`

### Validation Code

```php
// Return URL validation
if (str_starts_with($url, '//') ||
    preg_match('#^https?://#i', $url) ||
    str_contains($url, "\n") ||
    str_contains($url, "\r")
) {
    throw new InvalidReturnUrlException();
}
```

---

## Logout Security

### CSRF-Protected Logout

Logout requires POST method with CSRF token:

```twig
{# Using Twig component (recommended) #}
<twig:EuripSso:Logout />

{# Manual form #}
<form action="{{ path('eurip_sso_logout') }}" method="POST">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token('eurip_sso_logout') }}">
    <button type="submit">Logout</button>
</form>
```

### RP-Initiated Logout

When `end_session_endpoint` is available, the bundle redirects to the IdP for full SSO logout:
- Sends `id_token_hint` for session identification
- Sends `post_logout_redirect_uri` for return URL

### Back-Channel Logout

Configure for server-to-server logout notifications:

```yaml
eurip_sso:
    routes:
        backchannel_logout: /auth/backchannel-logout
```

---

## Security Checklist

- [ ] `requireHttps: true` (default) in production
- [ ] `verify_signature: true` (default) enabled
- [ ] Session storage configured correctly
- [ ] CORS properly configured for API endpoints
- [ ] Logout uses POST with CSRF token
- [ ] Return URLs validated (automatic)
- [ ] Cache warmed up after deployment

---

## Reporting Security Issues

Found a security vulnerability? Please report it privately:
- **Email:** security@example.com
- **Do NOT** create public GitHub issues for security vulnerabilities
