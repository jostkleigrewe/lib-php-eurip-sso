# Standalone Usage

The OIDC client classes can be used without the Symfony bundle, making them suitable for any PHP application.

## Requirements

- PHP 8.4+
- PSR-18 HTTP Client (`psr/http-client`)
- PSR-17 HTTP Factories (`psr/http-factory`)
- Optional: PSR-6 or PSR-16 Cache

## Using OidcClientFactory

The factory handles auto-discovery and caching:

```php
use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;

// Basic usage
$client = OidcClientFactory::create(
    issuer: 'https://sso.example.com',
    clientId: 'my-app',
    redirectUri: 'https://app.com/callback',
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    streamFactory: $streamFactory,
);

// With all options
$client = OidcClientFactory::create(
    issuer: 'https://sso.example.com',
    clientId: 'my-app',
    redirectUri: 'https://app.com/callback',
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    streamFactory: $streamFactory,
    clientSecret: 'secret',              // For confidential clients
    publicIssuer: 'https://public-sso.example.com',  // Docker/K8s
    cache: $symfonyCache,                // Symfony CacheInterface
    cacheTtl: 3600,                      // 1 hour
    logger: $logger,                     // PSR-3 Logger
    requireHttps: true,                  // HTTPS enforcement
);
```

### Factory Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `issuer` | string | Yes | - | OIDC issuer URL |
| `clientId` | string | Yes | - | Client ID |
| `redirectUri` | string | Yes | - | Callback URL |
| `httpClient` | ClientInterface | Yes | - | PSR-18 HTTP client |
| `requestFactory` | RequestFactoryInterface | Yes | - | PSR-17 request factory |
| `streamFactory` | StreamFactoryInterface | Yes | - | PSR-17 stream factory |
| `clientSecret` | string | No | `null` | Client secret |
| `publicIssuer` | string | No | `null` | Public issuer for browser redirects |
| `cache` | CacheInterface | No | `null` | Symfony cache |
| `cacheTtl` | int | No | `3600` | Cache TTL in seconds |
| `logger` | LoggerInterface | No | `null` | PSR-3 logger |
| `requireHttps` | bool | No | `true` | Enforce HTTPS |

---

## Using OidcClient Directly

For full control, construct the client manually:

```php
use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;

// 1. Create configuration
$config = new OidcClientConfig(
    clientId: 'my-app',
    issuer: 'https://sso.example.com',
    authorizationEndpoint: 'https://sso.example.com/authorize',
    tokenEndpoint: 'https://sso.example.com/token',
    jwksUri: 'https://sso.example.com/.well-known/jwks.json',
    redirectUri: 'https://app.com/callback',
    userInfoEndpoint: 'https://sso.example.com/userinfo',
    endSessionEndpoint: 'https://sso.example.com/logout',
);

// 2. Create JWT verifier
$jwtVerifier = new JwtVerifier(
    jwksUri: $config->jwksUri,
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    logger: $logger,
    cache: $cache,
    cacheKey: 'my_app.jwks',
    cacheTtl: 600,
);

// 3. Create client
$client = new OidcClient(
    $config,
    $httpClient,
    $requestFactory,
    $streamFactory,
    $jwtVerifier,
    $logger,
);
```

---

## Authentication Flow

### Step 1: Build Authorization URL

```php
// Build URL with PKCE
$authData = $client->buildAuthorizationUrl(['openid', 'profile', 'email']);

// Store these in session for callback validation
$_SESSION['oidc_state'] = $authData['state'];
$_SESSION['oidc_nonce'] = $authData['nonce'];
$_SESSION['oidc_code_verifier'] = $authData['code_verifier'];

// Redirect user to IdP
header('Location: ' . $authData['url']);
exit;
```

### Step 2: Handle Callback

```php
// Validate state
if (!hash_equals($_SESSION['oidc_state'], $_GET['state'])) {
    throw new Exception('Invalid state');
}

// Check for errors
if (isset($_GET['error'])) {
    throw new Exception($_GET['error'] . ': ' . ($_GET['error_description'] ?? ''));
}

// Exchange code for tokens
$tokens = $client->exchangeCode(
    $_GET['code'],
    $_SESSION['oidc_code_verifier']
);

// Decode and validate ID token
$claims = $client->decodeIdToken($tokens->idToken);
$client->validateClaims($claims, $_SESSION['oidc_nonce']);

// Clean up session
unset($_SESSION['oidc_state'], $_SESSION['oidc_nonce'], $_SESSION['oidc_code_verifier']);

// User is authenticated
$userId = $claims['sub'];
$email = $claims['email'] ?? null;
```

### Step 3: Get User Info (Optional)

```php
$userInfo = $client->getUserInfo($tokens->accessToken);
```

### Step 4: Logout

```php
$logoutUrl = $client->buildLogoutUrl(
    $idToken,
    'https://app.com/logged-out'  // Post-logout redirect
);

header('Location: ' . $logoutUrl);
```

---

## JwtVerifier Usage

The `JwtVerifier` class handles JWT signature verification:

```php
use Jostkleigrewe\Sso\Client\JwtVerifier;

$verifier = new JwtVerifier(
    jwksUri: 'https://sso.example.com/.well-known/jwks.json',
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    logger: $logger,
    cache: $cache,           // Optional: Symfony CacheInterface
    cacheKey: 'app.jwks',    // Optional: Custom cache key
    cacheTtl: 600,           // Optional: Cache TTL (default: 600s)
);

// Verify a JWT
$isValid = $verifier->verifySignature($jwt);

// Pre-load JWKS (e.g., during deployment)
$verifier->fetchAndCacheJwks();

// Check if JWKS is cached
if (!$verifier->hasJwksLoaded()) {
    $verifier->fetchAndCacheJwks();
}

// Clear cache (e.g., after key rotation)
$verifier->invalidateJwksCache();
```

### Key Rotation Resilience

The verifier automatically handles key rotation:
1. Attempts verification with cached keys
2. If verification fails, clears cache
3. Fetches fresh JWKS from provider
4. Retries verification

---

## Caching

### With Symfony Cache

```php
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

$cache = new FilesystemAdapter(
    namespace: 'oidc',
    defaultLifetime: 3600,
    directory: '/tmp/cache'
);

$client = OidcClientFactory::create(
    // ...
    cache: $cache,
    cacheTtl: 3600,
);
```

### With PSR-6 Cache (via Adapter)

```php
use Symfony\Component\Cache\Adapter\Psr16Adapter;

// Wrap PSR-16 cache in Symfony adapter
$symfonyCache = new Psr16Adapter($psr16Cache);

$client = OidcClientFactory::create(
    // ...
    cache: $symfonyCache,
);
```

### Cache Keys

The factory generates cache keys automatically:
- Discovery: `eurip_sso.discovery.v1.<hash>`
- JWKS: `eurip_sso.jwks.v1.<hash>`

---

## Error Handling

```php
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\InsecureUrlException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;

try {
    $client = OidcClientFactory::create(...);
    $tokens = $client->exchangeCode($code, $verifier);
    $claims = $client->decodeIdToken($tokens->idToken);
    $client->validateClaims($claims, $nonce);
} catch (InsecureUrlException $e) {
    // Non-HTTPS URL when requireHttps is true
} catch (OidcProtocolException $e) {
    // Discovery failed, invalid response, etc.
} catch (TokenExchangeFailedException $e) {
    // Token exchange failed
} catch (ClaimsValidationException $e) {
    // Invalid claims (expired, wrong issuer, etc.)
}
```

---

## Complete Example

```php
<?php

declare(strict_types=1);

use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\HttpClient\Psr18Client;

// Setup PSR-18 client (using Symfony HttpClient)
$httpClient = new Psr18Client();
$requestFactory = $httpClient;
$streamFactory = $httpClient;

// Setup cache
$cache = new FilesystemAdapter('oidc', 3600, '/tmp/cache');

// Create OIDC client
$client = OidcClientFactory::create(
    issuer: 'https://sso.example.com',
    clientId: 'my-app',
    redirectUri: 'https://app.com/callback',
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    streamFactory: $streamFactory,
    cache: $cache,
);

// Start login
if ($_SERVER['REQUEST_URI'] === '/login') {
    $authData = $client->buildAuthorizationUrl(['openid', 'profile', 'email']);
    $_SESSION['oidc'] = $authData;
    header('Location: ' . $authData['url']);
    exit;
}

// Handle callback
if ($_SERVER['REQUEST_URI'] === '/callback') {
    $authData = $_SESSION['oidc'];

    if (!hash_equals($authData['state'], $_GET['state'])) {
        die('Invalid state');
    }

    $tokens = $client->exchangeCode($_GET['code'], $authData['code_verifier']);
    $claims = $client->decodeIdToken($tokens->idToken);
    $client->validateClaims($claims, $authData['nonce']);

    $_SESSION['user'] = [
        'id' => $claims['sub'],
        'email' => $claims['email'] ?? null,
        'name' => $claims['name'] ?? null,
    ];

    unset($_SESSION['oidc']);
    header('Location: /');
    exit;
}
```

---

## See Also

- [Security Features](SECURITY.md) - HTTPS enforcement, JWT verification
- [Configuration](CONFIGURATION.md) - Bundle configuration (if using Symfony)
