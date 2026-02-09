# Services Reference

The EURIP SSO Bundle provides several services for working with authentication and authorization.

## Available Services

| Service | Purpose |
|---------|---------|
| `EuripSsoClaimsService` | Access ID token claims |
| `EuripSsoAuthorizationService` | Permission and role checks |
| `EuripSsoApiClient` | API calls to SSO server |
| `EuripSsoTokenStorage` | Token storage access |
| `OidcClient` | Low-level OIDC client |
| `JwtVerifier` | JWT signature verification |

---

## EuripSsoClaimsService

Access claims from the ID token of the currently logged-in user.

### Injection

```php
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;

public function __construct(
    private readonly EuripSsoClaimsService $claims,
) {}
```

### Standard Claims

```php
// Basic user info
$email = $this->claims->getEmail();        // string|null
$name = $this->claims->getName();          // string|null
$userId = $this->claims->getUserId();      // string (subject)
$locale = $this->claims->getLocale();      // string|null
```

### Client-Specific Claims (EURIP SSO)

```php
// Roles
$roles = $this->claims->getRoles();              // array - Global roles
$clientRoles = $this->claims->getClientRoles(); // array - Client-specific roles

// Permissions and groups
$permissions = $this->claims->getClientPermissions();  // array
$groups = $this->claims->getClientGroups();            // array

// Status
$isBlocked = $this->claims->isBlocked();  // bool
```

### Generic Access

```php
// Get any claim
$value = $this->claims->get('custom_claim', 'default');

// Get all claims
$allClaims = $this->claims->all();  // array
```

---

## EuripSsoAuthorizationService

Check permissions and roles for the current user.

### Injection

```php
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoAuthorizationService;

public function __construct(
    private readonly EuripSsoAuthorizationService $auth,
) {}
```

### Check Methods (Return bool)

```php
// Role checks
$auth->hasRole('ROLE_ADMIN');          // Check Symfony role
$auth->hasClientRole('editor');        // Check SSO client role

// Permission checks
$auth->hasPermission('edit:article');
$auth->hasAnyPermission(['edit:article', 'delete:article']);
$auth->hasAllPermissions(['view:article', 'edit:article']);

// Group check
$auth->isInGroup('editors');

// Access check (not blocked)
$auth->canAccess();
```

### Require Methods (Throw Exception)

These methods throw `PermissionDeniedException` if the check fails:

```php
// Throws if user doesn't have role
$auth->requireRole('ROLE_ADMIN');

// Throws if user doesn't have permission
$auth->requirePermission('edit:article');

// Throws if user is blocked
$auth->requireAccess();
```

### Usage Example

```php
#[Route('/article/{id}/edit')]
public function edit(int $id): Response
{
    // Require permission (throws 403 if missing)
    $this->auth->requirePermission('edit:article');

    // Check for optional feature
    $canPublish = $this->auth->hasPermission('publish:article');

    return $this->render('article/edit.html.twig', [
        'canPublish' => $canPublish,
    ]);
}
```

---

## EuripSsoApiClient

Make authenticated API calls to the SSO server.

### Injection

```php
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoApiClient;

public function __construct(
    private readonly EuripSsoApiClient $api,
) {}
```

### Methods

```php
// Get user info from userinfo endpoint
$userInfo = $this->api->getUserInfo();

// Make custom API call
$response = $this->api->get('/api/users');
$response = $this->api->post('/api/action', ['data' => 'value']);
```

---

## EuripSsoTokenStorage

Access stored tokens for the current session.

### Injection

```php
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;

public function __construct(
    private readonly EuripSsoTokenStorage $tokenStorage,
) {}
```

### Methods

```php
// Get tokens
$accessToken = $this->tokenStorage->getAccessToken();
$idToken = $this->tokenStorage->getIdToken();
$refreshToken = $this->tokenStorage->getRefreshToken();

// Check token availability
$hasToken = $this->tokenStorage->hasAccessToken();
```

---

## OidcClient

Low-level OIDC client for custom integrations.

### Injection

```php
use Jostkleigrewe\Sso\Client\OidcClient;

public function __construct(
    private readonly OidcClient $oidcClient,
) {}
```

### Methods

```php
// Build authorization URL
$authData = $this->oidcClient->buildAuthorizationUrl(['openid', 'profile']);
// Returns: ['url' => '...', 'state' => '...', 'nonce' => '...', 'code_verifier' => '...']

// Exchange code for tokens
$tokens = $this->oidcClient->exchangeCode($code, $codeVerifier);

// Decode ID token (without verification)
$claims = $this->oidcClient->decodeIdToken($idToken);

// Validate claims
$this->oidcClient->validateClaims($claims, $nonce);

// Get user info
$userInfo = $this->oidcClient->getUserInfo($accessToken);

// Refresh token
$newTokens = $this->oidcClient->refreshToken($refreshToken);

// Build logout URL
$logoutUrl = $this->oidcClient->buildLogoutUrl($idToken, $redirectUri);
```

---

## JwtVerifier

Verify JWT signatures using JWKS.

### Injection

```php
use Jostkleigrewe\Sso\Client\JwtVerifier;

public function __construct(
    private readonly JwtVerifier $jwtVerifier,
) {}
```

### Methods

```php
// Verify signature
$isValid = $this->jwtVerifier->verifySignature($jwt);

// Preload JWKS (for cache warmup)
$this->jwtVerifier->fetchAndCacheJwks();

// Check if JWKS is cached
$isCached = $this->jwtVerifier->hasJwksLoaded();

// Clear JWKS cache
$this->jwtVerifier->invalidateJwksCache();
```

---

## Controller Example

Complete example combining multiple services:

```php
<?php

declare(strict_types=1);

namespace App\Controller;

use Jostkleigrewe\Sso\Bundle\Service\EuripSsoAuthorizationService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class DashboardController extends AbstractController
{
    public function __construct(
        private readonly EuripSsoAuthorizationService $auth,
        private readonly EuripSsoClaimsService $claims,
    ) {}

    #[Route('/dashboard', name: 'dashboard')]
    public function index(): Response
    {
        // Ensure user can access
        $this->auth->requireAccess();

        return $this->render('dashboard/index.html.twig', [
            'userName' => $this->claims->getName(),
            'email' => $this->claims->getEmail(),
            'roles' => $this->claims->getClientRoles(),
            'isAdmin' => $this->auth->hasRole('ROLE_ADMIN'),
            'canManageUsers' => $this->auth->hasPermission('manage:users'),
        ]);
    }

    #[Route('/admin', name: 'admin')]
    public function admin(): Response
    {
        // Only admins can access
        $this->auth->requireRole('ROLE_ADMIN');

        return $this->render('admin/index.html.twig');
    }
}
```

---

## See Also

- [Events](EVENTS.md) - Customize the authentication flow
- [Configuration](CONFIGURATION.md) - Service configuration options
- [Standalone Usage](STANDALONE.md) - Using services without the bundle
