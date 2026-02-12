# Machine-to-Machine (M2M) Authentication

[Deutsche Version](M2M-AUTHENTICATION.de.md)

## Overview

This guide covers authentication flows for **server-to-server communication** where no user is involved. Two complementary features are covered:

| Feature | RFC | Purpose |
|---------|-----|---------|
| **Client Credentials Grant** | RFC 6749 §4.4 | Get access token without user interaction |
| **Token Introspection** | RFC 7662 | Validate incoming tokens (for APIs/Resource Servers) |

### Common Use Cases

- **Cronjobs** - Nightly sync jobs calling APIs
- **Microservices** - Service A authenticates to Service B
- **Backend Integrations** - ERP systems, data pipelines
- **Webhooks** - Your server calling external APIs
- **Resource Servers** - APIs validating incoming Bearer tokens

## How It Works

### Client Credentials Grant

```
┌─────────────────┐                              ┌─────────────────┐
│  Your Server    │                              │  SSO Server     │
│  (e.g., Cronjob)│                              │                 │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  POST /oidc/token                              │
         │  grant_type=client_credentials                 │
         │  client_id + client_secret                     │
         │  scope=api:read                                │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  { access_token, expires_in, scope }           │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         ▼                                                ▼

No id_token - there's no user identity
No refresh_token - client can always request a new token
```

### Token Introspection

```
┌─────────────────┐                              ┌─────────────────┐
│  Resource Server│                              │  SSO Server     │
│  (Your API)     │                              │                 │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  POST /oidc/introspect                         │
         │  token=<incoming bearer token>                 │
         │  client_id + client_secret                     │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  { active: true, scope, client_id, exp, ... }  │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         ▼                                                ▼
```

## Prerequisites

### SSO Server Requirements

Check if your OIDC provider supports these features:

```bash
# Check discovery document
curl https://sso.example.com/.well-known/openid-configuration | jq '{
  grant_types: .grant_types_supported,
  introspection: .introspection_endpoint
}'
```

Expected output:
```json
{
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "introspection": "https://sso.example.com/oidc/introspect"
}
```

### Client Configuration

Your client must be configured in the SSO admin:

| Setting | Value |
|---------|-------|
| Client Type | Confidential |
| Client Secret | Required |
| Allowed Grant Types | `client_credentials` |
| Allowed Scopes | As needed (e.g., `api:read`, `api:write`) |

### Bundle Configuration

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    client_secret: '%env(OIDC_CLIENT_SECRET)%'  # Required!
    redirect_uri: '%env(APP_URL)%/auth/callback'
```

## Usage

### CLI Commands

#### Get Token via Client Credentials

```bash
# Interactive - shows token details
bin/console eurip:sso:client-credentials

# With specific scopes
bin/console eurip:sso:client-credentials --scopes="api:read,api:write"

# Output only token (for scripting)
TOKEN=$(bin/console eurip:sso:client-credentials --output-token)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data

# JSON output
bin/console eurip:sso:client-credentials --output-json
```

#### Introspect a Token

```bash
# Validate and inspect token
bin/console eurip:sso:introspect "eyJhbGciOiJSUzI1NiIs..."

# With token type hint (speeds up lookup)
bin/console eurip:sso:introspect "$TOKEN" --type=access_token

# JSON output
bin/console eurip:sso:introspect "$TOKEN" --output-json
```

### Programmatic Usage

#### Client Credentials Grant

```php
use Jostkleigrewe\Sso\Client\OidcClient;

class OrderSyncCommand extends Command
{
    public function __construct(
        private OidcClient $oidcClient,
        private HttpClientInterface $httpClient,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // 1. Get access token (no user interaction!)
        $token = $this->oidcClient->getClientCredentialsToken(
            scopes: ['orders:read']
        );

        // 2. Call protected API
        $response = $this->httpClient->request('GET',
            'https://api.example.com/orders',
            [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token->accessToken,
                ],
            ]
        );

        // 3. Process data
        $orders = $response->toArray();

        foreach ($orders as $order) {
            $this->processOrder($order);
        }

        return Command::SUCCESS;
    }
}
```

#### Token Introspection (Resource Server)

```php
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

class ApiController
{
    public function __construct(
        private OidcClient $oidcClient,
    ) {}

    public function getOrders(Request $request): JsonResponse
    {
        // 1. Extract Bearer token
        $authHeader = $request->headers->get('Authorization', '');
        if (!str_starts_with($authHeader, 'Bearer ')) {
            return new JsonResponse(['error' => 'Missing bearer token'], 401);
        }
        $token = substr($authHeader, 7);

        // 2. Validate token via introspection
        $introspection = $this->oidcClient->introspectToken($token);

        if (!$introspection->active) {
            return new JsonResponse(['error' => 'Invalid or expired token'], 401);
        }

        // 3. Check required scope
        if (!$introspection->hasScope('orders:read')) {
            return new JsonResponse(['error' => 'Insufficient scope'], 403);
        }

        // 4. Process request
        return new JsonResponse([
            'orders' => $this->orderRepository->findAll(),
            'client_id' => $introspection->clientId,
        ]);
    }
}
```

#### Symfony Security Authenticator

For a more integrated approach, create a custom authenticator:

```php
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class BearerTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private OidcClient $oidcClient,
    ) {}

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization')
            && str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $token = substr($request->headers->get('Authorization', ''), 7);

        $introspection = $this->oidcClient->introspectToken($token);

        if (!$introspection->active) {
            throw new AuthenticationException('Token is not active');
        }

        // Create a "machine user" representing the client
        return new SelfValidatingPassport(
            new UserBadge(
                $introspection->clientId ?? 'unknown',
                fn () => new MachineUser(
                    clientId: $introspection->clientId,
                    scopes: $introspection->getScopes(),
                    subject: $introspection->sub,
                )
            )
        );
    }
}
```

## API Reference

### OidcClient Methods

#### getClientCredentialsToken()

```php
/**
 * @param list<string> $scopes Requested scopes (optional)
 * @return TokenResponse Access token (no id_token, usually no refresh_token)
 * @throws OidcProtocolException If no client_secret is configured
 * @throws TokenExchangeFailedException On provider errors
 */
public function getClientCredentialsToken(array $scopes = []): TokenResponse
```

#### introspectToken()

```php
/**
 * @param string $token The token to validate
 * @param string|null $tokenTypeHint Optional: "access_token" or "refresh_token"
 * @return IntrospectionResponse Token metadata (active, scope, client_id, exp, etc.)
 * @throws OidcProtocolException If no introspection_endpoint is configured
 */
public function introspectToken(string $token, ?string $tokenTypeHint = null): IntrospectionResponse
```

### TokenResponse

Returned by `getClientCredentialsToken()`:

| Property | Type | Description |
|----------|------|-------------|
| `accessToken` | `string` | The access token |
| `tokenType` | `string` | Usually "Bearer" |
| `expiresIn` | `int` | Token lifetime in seconds |
| `expiresAt` | `DateTimeImmutable` | Calculated expiration timestamp |
| `scope` | `?string` | Granted scopes (space-separated) |
| `refreshToken` | `?string` | Usually null for client credentials |
| `idToken` | `?string` | Always null for client credentials |

**Helper Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `isExpired()` | `bool` | Whether the token has expired |
| `isExpiringSoon(int $buffer = 60)` | `bool` | Whether token expires within buffer |
| `getRemainingSeconds()` | `int` | Seconds until expiration |

### IntrospectionResponse

Returned by `introspectToken()`:

| Property | Type | Description |
|----------|------|-------------|
| `active` | `bool` | Whether the token is valid (REQUIRED) |
| `scope` | `?string` | Token scope (space-separated) |
| `clientId` | `?string` | Client the token was issued for |
| `username` | `?string` | Human-readable identifier |
| `sub` | `?string` | Subject identifier (user ID) |
| `tokenType` | `?string` | Token type (e.g., "Bearer") |
| `exp` | `?int` | Expiration timestamp (Unix) |
| `iat` | `?int` | Issued at timestamp (Unix) |
| `nbf` | `?int` | Not before timestamp (Unix) |
| `aud` | `?string` | Intended audience |
| `iss` | `?string` | Issuer URI |
| `jti` | `?string` | JWT ID (unique identifier) |

**Helper Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `hasScope(string $scope)` | `bool` | Whether token has specific scope |
| `getScopes()` | `list<string>` | All scopes as array |
| `isExpired()` | `bool` | Whether token has expired |
| `getRemainingSeconds()` | `int` | Seconds until expiration |

## Complete Example: ERP Order Sync

### The Scenario

An ERP system syncs orders from a Shop API every night at 02:00.

### Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  02:00 Cronjob triggers                                        │
│                                                                │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│  │   ERP       │     │   SSO       │     │   Shop      │      │
│  │   Cronjob   │     │   Server    │     │   API       │      │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘      │
│         │                   │                   │              │
│         │  1. Get Token     │                   │              │
│         │ ─────────────────►│                   │              │
│         │ ◄─────────────────│                   │              │
│         │                   │                   │              │
│         │  2. GET /orders (Bearer token)        │              │
│         │ ──────────────────────────────────────►              │
│         │                   │                   │              │
│         │                   │  3. Introspect    │              │
│         │                   │ ◄─────────────────│              │
│         │                   │ ─────────────────►│              │
│         │                   │                   │              │
│         │  4. Orders JSON                       │              │
│         │ ◄──────────────────────────────────────              │
│         │                   │                   │              │
│         ▼                   ▼                   ▼              │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### ERP Side (Client)

```php
// src/Command/SyncOrdersCommand.php

#[AsCommand(name: 'erp:sync-orders')]
final class SyncOrdersCommand extends Command
{
    public function __construct(
        private OidcClient $oidcClient,
        private HttpClientInterface $httpClient,
        private OrderImporter $importer,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // 1. Get M2M token
        $token = $this->oidcClient->getClientCredentialsToken(['orders:read']);
        $io->info(sprintf('Token obtained, expires in %ds', $token->expiresIn));

        // 2. Fetch orders from Shop API
        $response = $this->httpClient->request('GET',
            'https://shop.example.com/api/orders?since=yesterday',
            [
                'headers' => ['Authorization' => 'Bearer ' . $token->accessToken],
            ]
        );

        $orders = $response->toArray();
        $io->info(sprintf('Fetched %d orders', count($orders)));

        // 3. Import orders
        foreach ($orders as $order) {
            $this->importer->import($order);
        }

        $io->success('Order sync completed');

        return Command::SUCCESS;
    }
}
```

### Shop API Side (Resource Server)

```php
// src/Security/BearerTokenAuthenticator.php

final class BearerTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private OidcClient $oidcClient,
    ) {}

    public function authenticate(Request $request): Passport
    {
        $token = $this->extractBearerToken($request);
        $introspection = $this->oidcClient->introspectToken($token, 'access_token');

        if (!$introspection->active) {
            throw new AuthenticationException('Token is inactive');
        }

        return new SelfValidatingPassport(
            new UserBadge(
                $introspection->clientId ?? 'api-client',
                fn () => new ApiClient(
                    clientId: $introspection->clientId,
                    scopes: $introspection->getScopes(),
                )
            )
        );
    }

    private function extractBearerToken(Request $request): string
    {
        $header = $request->headers->get('Authorization', '');

        if (!str_starts_with($header, 'Bearer ')) {
            throw new AuthenticationException('Missing Bearer token');
        }

        return substr($header, 7);
    }
}
```

## Security Considerations

### Client Credentials

1. **Protect Client Secret** - Store in environment variables, never commit
2. **Use Minimal Scopes** - Request only what you need
3. **Short Token Lifetime** - Configure tokens to expire quickly (1 hour typical)
4. **Rotate Secrets** - Periodically rotate client secrets

### Token Introspection

1. **Always Validate** - Never trust tokens without validation
2. **Check Scopes** - Verify the token has required permissions
3. **Handle Revocation** - Tokens can be revoked mid-lifetime
4. **Cache Carefully** - Balance performance vs. revocation detection

### Introspection vs. Local JWT Validation

| Aspect | Introspection | Local JWT Validation |
|--------|---------------|---------------------|
| Revocation | Immediate | Delayed (until expiry) |
| Latency | HTTP call required | No network needed |
| SSO Dependency | Must be reachable | Only for JWKS updates |
| Recommended For | High security, revocation needed | High throughput, latency-sensitive |

## Troubleshooting

### "Client credentials grant requires a client_secret"

**Cause:** No `client_secret` configured in `eurip_sso.yaml`.

**Solution:** Add the secret to your configuration:
```yaml
eurip_sso:
    client_secret: '%env(OIDC_CLIENT_SECRET)%'
```

### "unauthorized_client" Error

**Cause:** The client is not authorized for `client_credentials` grant.

**Solution:** In SSO admin, enable `client_credentials` in the client's allowed grant types.

### "invalid_scope" Error

**Cause:** Requested scope is not allowed for this client.

**Solution:** Check the client's allowed scopes in SSO admin.

### "No introspection_endpoint configured"

**Cause:** The OIDC provider doesn't expose an introspection endpoint.

**Solution:** Either:
1. Enable introspection on the SSO server
2. Use local JWT validation instead (if access tokens are JWTs)

### Token Always Returns `active: false`

**Possible causes:**
1. Token has expired
2. Token was revoked
3. Token was issued by a different client
4. Token format is invalid
5. Wrong token type (refresh vs access)

**Debug:** Use `--output-json` with the introspect command to see details.

## References

- [RFC 6749 - OAuth 2.0 (Client Credentials)](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- [RFC 7662 - Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [OAuth 2.0 Token Introspection (oauth.net)](https://oauth.net/2/token-introspection/)
