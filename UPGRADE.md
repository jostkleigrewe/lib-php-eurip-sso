# Upgrade Guide

This document covers breaking changes and migration steps between major versions.

## Upgrading to v0.3.x

### Breaking Changes

#### 1. JwtVerifier Extraction

JWKS handling has been moved from `OidcClient` to a dedicated `JwtVerifier` class.

**Removed Methods from OidcClient:**
- `preloadJwks()` - Use `$jwtVerifier->fetchAndCacheJwks()` instead
- `fetchAndCacheJwks()` - Use `$jwtVerifier->fetchAndCacheJwks()` instead
- `hasJwksLoaded()` - Use `$jwtVerifier->hasJwksLoaded()` instead
- `invalidateJwksCache()` - Use `$jwtVerifier->invalidateJwksCache()` instead
- `fromDiscovery()` - Use `OidcClientFactory::create()` instead

**Changed Constructor:**
```php
// Before (v0.2.x)
$client = new OidcClient($config, $httpClient, $requestFactory, $streamFactory, $logger);

// After (v0.3.x)
$jwtVerifier = new JwtVerifier($jwksUri, $httpClient, $requestFactory, $logger, $cache);
$client = new OidcClient($config, $httpClient, $requestFactory, $streamFactory, $jwtVerifier, $logger);
```

**Migration:**
```php
// Before
$client = OidcClient::fromDiscovery($issuer, $clientId, $redirectUri, $httpClient, ...);
$client->preloadJwks();

// After
$client = OidcClientFactory::create(
    issuer: $issuer,
    clientId: $clientId,
    redirectUri: $redirectUri,
    httpClient: $httpClient,
    ...
);
// JWKS is automatically preloaded by factory
```

#### 2. Removed Classes

| Removed | Replacement |
|---------|-------------|
| `EuripSsoFacade` | Direct service injection |
| `OidcController` | `AuthenticationController`, `ProfileController`, `DiagnosticsController` |
| `OidcRouteLoader` | Routes use `#[Route]` attributes |

#### 3. Removed Config Options

```yaml
# These options no longer exist in v0.3.x:
eurip_sso:
    controller:
        enabled: true  # REMOVED - Controllers always active
    client_services:
        enabled: true  # REMOVED - Services always registered
        store_access_token: true  # REMOVED
    authenticator:
        callback_route: ~     # REMOVED
        default_target_path: ~ # REMOVED
        login_path: ~         # REMOVED
```

#### 4. Removed Service Aliases

| Removed Alias | Use Instead |
|---------------|-------------|
| `eurip_sso.facade` | `EuripSsoFacade` (removed) |
| `eurip_sso.claims` | `EuripSsoClaimsService` (FQCN) |
| `eurip_sso.auth` | `EuripSsoAuthorizationService` (FQCN) |
| `eurip_sso.api` | `EuripSsoApiClient` (FQCN) |
| `eurip_sso.token_storage` | `EuripSsoTokenStorage` (FQCN) |

**Migration:**
```php
// Before
public function __construct(
    #[Autowire(service: 'eurip_sso.claims')] private $claims,
) {}

// After
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;

public function __construct(
    private readonly EuripSsoClaimsService $claims,
) {}
```

#### 5. Event Dispatch Changes

Event `::NAME` constants have been removed. Use class-based dispatch (Symfony standard).

```php
// Before
#[AsEventListener(event: OidcLoginSuccessEvent::NAME)]
public function onLogin(OidcLoginSuccessEvent $event): void {}

// After
#[AsEventListener]
public function __invoke(OidcLoginSuccessEvent $event): void {}
```

### New Features in v0.3.x

- **JwtVerifier** - Dedicated class for JWT signature verification
- **HTTPS Enforcement** - `requireHttps` option (default: `true`)
- **Controller Split** - Separate controllers for auth, profile, diagnostics
- **Console Commands** - `eurip:sso:cache-warmup`, `eurip:sso:test-connection`
- **Back-Channel Logout** - OIDC RP-Initiated Logout support
- **Front-Channel Logout** - iframe-based logout support

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes.

---

## Upgrading to v0.2.x

### New Features

- Zero-Code Integration via configuration
- Automatic User Provisioning with Doctrine
- 5 new events for authentication lifecycle
- Session-based state/nonce storage

### Migration from v0.1.x

1. Update `composer.json`:
   ```bash
   composer require jostkleigrewe/lib-php-eurip-sso:^0.2
   ```

2. Configure the bundle (see [Installation Guide](docs/INSTALL.md))

3. Remove custom auth controller if using zero-code integration

4. Update event listeners to new event names (if using custom listeners)
