# EURIP SSO Bundle

OIDC Client Library and Symfony Bundle for Single Sign-On.

🇩🇪 [Deutsche Version](README.de.md)

## Features

- **Zero-Code Integration** - Complete OIDC auth via configuration only
- OIDC Authorization Code Flow with PKCE (S256)
- Auto-Discovery via `.well-known/openid-configuration`
- Dual-URL Support (internal/public issuer for Docker/K8s)
- Automatic User Provisioning with Doctrine
- Hybrid User Strategy (sync SSO data, preserve local data)
- Extensive Event System (9 events, class-based dispatch)
- JWT Signature Verification via dedicated `JwtVerifier` with key-rotation resilience
- PSR-3 Logging, PSR-18 HTTP Client
- **Security**: JWT signature verification, timing-safe comparisons, open redirect protection

## Requirements

- PHP 8.4+
- Symfony 7.0+ or 8.0+
- PSR-18 HTTP Client

## Installation

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

```php
// config/bundles.php
Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
```

## Quick Start: Zero-Code Integration

### 1. Configure Bundle

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'

    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        after_login: /
        profile: /auth/profile
        debug: /auth/debug

    user_provider:
        enabled: true
        entity: App\Entity\User
        mapping:
            subject: oidcSubject
            issuer: oidcIssuer
            email: email
            roles: roles
            external_roles: externalRoles
        sync_on_login: true
        auto_create: true
```

### 2. Configure Security

```yaml
# config/packages/security.yaml
security:
    providers:
        app_user_provider:
            id: Jostkleigrewe\Sso\Bundle\Security\DoctrineOidcUserProvider

    firewalls:
        main:
            lazy: true
            provider: app_user_provider
            custom_authenticators:
                - Jostkleigrewe\Sso\Bundle\Security\OidcAuthenticator
```

**Done!** Routes available:
- `/auth/login` - Start login (GET)
- `/auth/callback` - SSO callback (GET)
- `/auth/logout` - Logout (POST with CSRF token)
- `/auth/logout/confirm` - Logout confirmation page (GET, optional)
- `/auth/profile` - User profile (GET)
- `/auth/debug` - OIDC config (GET)
- `/auth/test` - Auth test page (GET)

**Important:** The logout route requires POST with CSRF token:
```twig
{# Option A: Twig Component (recommended) #}
<twig:EuripSso:Logout />

{# Option B: Manual form #}
<form action="{{ path('eurip_sso_logout') }}" method="POST">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token('eurip_sso_logout') }}">
    <button type="submit">Logout</button>
</form>
```

## Architecture

### Controllers

The bundle provides three controllers, registered via `#[Route]` attributes with configurable paths:

| Controller | Routes | Purpose |
|------------|--------|---------|
| `AuthenticationController` | login, callback, logout, logout_confirm | Core auth flow |
| `ProfileController` | profile | User profile page |
| `DiagnosticsController` | debug, test | Debug & test pages |

### Services

All services are auto-registered via resource scanning. Inject them directly:

```php
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoAuthorizationService;

public function __construct(
    private readonly EuripSsoAuthorizationService $auth,
    private readonly EuripSsoClaimsService $claims,
) {}

public function edit(): Response
{
    // Require permission (throws PermissionDeniedException if missing)
    $this->auth->requirePermission('edit:article');

    // Access claims
    $email = $this->claims->getEmail();
    $userId = $this->claims->getUserId();
    $roles = $this->claims->getClientRoles();

    // Check permissions
    if ($this->auth->hasPermission('delete:article')) {
        // ...
    }
}
```

#### Available Services

| Service | Purpose |
|---------|---------|
| `EuripSsoClaimsService` | Access ID token claims |
| `EuripSsoAuthorizationService` | Permission/role checks |
| `EuripSsoApiClient` | API calls to SSO server |
| `EuripSsoTokenStorage` | Token storage access |
| `OidcClient` | Low-level OIDC client |
| `JwtVerifier` | JWT signature verification |

#### Authorization Methods

```php
// Check methods (return bool)
$auth->hasRole('ROLE_ADMIN');
$auth->hasClientRole('editor');
$auth->hasPermission('edit:article');
$auth->hasAnyPermission(['edit:article', 'delete:article']);
$auth->hasAllPermissions(['view:article', 'edit:article']);
$auth->isInGroup('editors');
$auth->canAccess();  // Not blocked

// Require methods (throw PermissionDeniedException)
$auth->requireRole('ROLE_ADMIN');
$auth->requirePermission('edit:article');
$auth->requireAccess();
```

#### Claims Access

```php
// Standard claims
$claims->getEmail();
$claims->getName();
$claims->getUserId();  // Subject
$claims->getLocale();

// Client-specific claims (EURIP SSO)
$claims->getRoles();            // Global roles
$claims->getClientRoles();      // Client-specific roles
$claims->getClientPermissions();
$claims->getClientGroups();
$claims->isBlocked();

// Generic access
$claims->get('custom_claim', 'default');
$claims->all();  // All claims as array
```

## Extending via Events

The bundle dispatches events at key points in the authentication flow. Events use **class-based dispatch** (Symfony standard).

### Event Overview

| Event | When | Available Methods |
|-------|------|-------------------|
| `OidcPreLoginEvent` | Before IdP redirect | `setScopes()`, `setResponse()` |
| `OidcLoginSuccessEvent` | After successful login | `addRole()`, `removeRole()`, `setTargetPath()`, `setResponse()` |
| `OidcLoginFailureEvent` | On authentication error | `setResponse()` |
| `OidcUserCreatedEvent` | New user created | Access `$entity`, `$claims` |
| `OidcUserUpdatedEvent` | Existing user synced | Access `$entity`, `$claims` |
| `OidcPreLogoutEvent` | Before logout | `skipSsoLogout()`, `setResponse()` |
| `OidcTokenRefreshedEvent` | After token refresh | Access `$tokenResponse` |
| `OidcBackchannelLogoutEvent` | Back-channel logout received | Access `$subject`, `$sessionId`, `$claims`, `markHandled()` |
| `OidcFrontchannelLogoutEvent` | Front-channel logout received | Access `$issuer`, `$sessionId`, `markHandled()` |

### Common Use Cases

#### Add Roles Based on Claims

```php
#[AsEventListener]
class AddAdminRoleListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // Add ROLE_ADMIN if user is in 'admins' group
        if (in_array('admins', $event->claims['groups'] ?? [])) {
            $event->addRole('ROLE_ADMIN');
        }
    }
}
```

#### Block Users Based on Claims

```php
#[AsEventListener]
class BlockInactiveUserListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        if ($event->claims['is_blocked'] ?? false) {
            $event->setResponse(new Response('Account blocked', 403));
        }
    }
}
```

#### Custom Redirect After Login

```php
#[AsEventListener]
class RedirectNewUserListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // Redirect first-time users to onboarding
        if (empty($event->claims['profile_complete'])) {
            $event->setTargetPath('/onboarding');
        }
    }
}
```

#### Send Welcome Email

```php
#[AsEventListener]
class WelcomeEmailListener
{
    public function __construct(private MailerInterface $mailer) {}

    public function __invoke(OidcUserCreatedEvent $event): void
    {
        $email = $event->claims['email'] ?? null;
        if ($email) {
            // Queue welcome email (entity not yet flushed!)
            $this->mailer->send(new WelcomeEmail($email));
        }
    }
}
```

#### Request Additional Scopes

```php
#[AsEventListener]
class AddScopesListener
{
    public function __invoke(OidcPreLoginEvent $event): void
    {
        $scopes = $event->getScopes();
        $scopes[] = 'custom:permissions';
        $event->setScopes($scopes);
    }
}
```

#### Skip SSO Logout (Local Only)

```php
#[AsEventListener]
class LocalLogoutOnlyListener
{
    public function __invoke(OidcPreLogoutEvent $event): void
    {
        // Only invalidate local session, don't redirect to SSO logout
        $event->skipSsoLogout();
    }
}
```

#### Custom Error Page

```php
#[AsEventListener]
class CustomErrorPageListener
{
    public function __construct(private Environment $twig) {}

    public function __invoke(OidcLoginFailureEvent $event): void
    {
        $html = $this->twig->render('auth/error.html.twig', [
            'error' => $event->error,
            'description' => $event->errorDescription,
        ]);
        $event->setResponse(new Response($html, 401));
    }
}
```

### Event Flow Diagram

```
Login Flow:
  ┌─────────────────┐
  │ OidcPreLoginEvent │ → Can modify scopes or abort
  └────────┬────────┘
           ↓
  [Redirect to IdP]
           ↓
  [User authenticates]
           ↓
  [Callback received]
           ↓
  ┌─────────────────────┐
  │ OidcUserCreatedEvent │ → Only for new users (before flush)
  │   OR                 │
  │ OidcUserUpdatedEvent │ → For existing users (before flush)
  └────────┬─────────────┘
           ↓
  ┌──────────────────────┐
  │ OidcLoginSuccessEvent │ → Modify roles, redirect, or block
  └────────┬─────────────┘
           ↓
  [User logged in]

Logout Flow:
  ┌──────────────────┐
  │ OidcPreLogoutEvent │ → Can skip SSO logout or abort
  └────────┬─────────┘
           ↓
  [Session invalidated]
           ↓
  [Redirect to SSO logout or after_logout path]
```

## User Strategy: Bundle vs. Custom Entity

The bundle provides `OidcUser`, a generic user class. Depending on your use case, you can use it directly or provide your own Doctrine entity.

### When to Use Bundle's OidcUser (No Custom Entity)

Use the built-in `OidcUser` class when:

- **Stateless/API-only** - No local user data needed
- **Simple apps** - Just need authentication, no user management
- **Microservices** - User data lives in another service

```yaml
eurip_sso:
    user_provider:
        enabled: false  # Don't use Doctrine provider
```

The `OidcUser` is created from claims on each login - no database required.

### When You Need a Custom Entity

Create your own User entity when you need:

| Requirement | Example |
|-------------|---------|
| **Local data** | User preferences, settings, avatar |
| **Local roles** | ROLE_ADMIN assigned manually in app |
| **Relations** | User has Orders, Posts, Comments |
| **User management** | Admin panel to list/edit users |
| **Audit trail** | Track user activity in your database |

```php
// src/Entity/User.php
#[ORM\Entity]
class User implements UserInterface
{
    #[ORM\Column(length: 255)]
    private ?string $oidcSubject = null;

    #[ORM\Column(length: 255)]
    private ?string $oidcIssuer = null;

    // Local data (not synced from SSO)
    #[ORM\Column(type: 'json')]
    private array $roles = ['ROLE_USER'];

    // SSO data (synced on each login)
    #[ORM\Column(type: 'json')]
    private array $externalRoles = [];

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $email = null;

    // App-specific fields
    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $preferences = null;

    // ... getters/setters
}
```

### Hybrid Role Strategy

When both `roles` and `external_roles` are mapped, roles are **merged**:

```yaml
user_provider:
    mapping:
        roles: roles              # Local roles (preserved)
        external_roles: externalRoles  # SSO roles (synced)
```

- **Local roles**: Set manually in your app (e.g., ROLE_ADMIN)
- **External roles**: Synced from SSO on each login
- **Effective roles**: Union of both (local + external)

### Decision Matrix

| Scenario | Solution |
|----------|----------|
| API gateway, no local state | `OidcUser` (no entity) |
| Simple web app, just login | `OidcUser` with `user_provider.enabled: true` |
| Need local preferences | Custom entity |
| Need local + SSO roles | Custom entity with hybrid mapping |
| Full user management | Custom entity implementing `UserInterface` |

## Configuration Reference

```yaml
eurip_sso:
    # Required
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'

    # Optional
    client_secret: null
    public_issuer: null              # For Docker/K8s
    scopes: [openid, profile, email]

    cache:
        enabled: true
        ttl: 3600
        pool: cache.app

    authenticator:
        enabled: true                # Register OidcAuthenticator for Symfony Security
        verify_signature: true       # JWT signature verification (recommended!)

    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        logout_confirm: /auth/logout/confirm
        after_login: /
        after_logout: /
        profile: /auth/profile
        debug: /auth/debug
        test: /auth/test
        # OpenID Connect Logout Extensions
        backchannel_logout: null    # POST endpoint for back-channel logout
        frontchannel_logout: null   # GET endpoint for front-channel logout (iframe)

    user_provider:
        enabled: false
        entity: null
        mapping:
            subject: oidcSubject     # Required: OIDC subject identifier
            issuer: oidcIssuer       # Required: OIDC issuer
            email: null              # Optional: email field
            roles: null              # Optional: local roles field
            external_roles: null     # Optional: SSO roles field
        claims_sync: {}              # Additional claim-to-field mapping
        roles_claim: roles           # Claim name for roles
        default_roles: [ROLE_USER]
        sync_on_login: true
        auto_create: true
```

## Console Commands

| Command | Purpose |
|---------|---------|
| `eurip:sso:cache-warmup` | Pre-fetch and cache OIDC discovery + JWKS |
| `eurip:sso:test-connection` | Test connection to the OIDC provider |

## Standalone Usage

The `OidcClient` and `JwtVerifier` can be used without the Symfony bundle:

```php
use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;

// Build config (e.g., from discovery document)
$config = new OidcClientConfig(
    clientId: 'my-app',
    issuer: 'https://sso.example.com',
    authorizationEndpoint: 'https://sso.example.com/authorize',
    tokenEndpoint: 'https://sso.example.com/token',
    jwksUri: 'https://sso.example.com/.well-known/jwks.json',
    redirectUri: 'https://app.com/callback',
    userInfoEndpoint: 'https://sso.example.com/userinfo',
);

$jwtVerifier = new JwtVerifier($config->jwksUri, $httpClient, $requestFactory);
$client = new OidcClient($config, $httpClient, $requestFactory, $streamFactory, $jwtVerifier);

// Build authorization URL
$authData = $client->buildAuthorizationUrl(['openid', 'profile']);
// Redirect to $authData['url']
// Store $authData['state'], $authData['nonce'], $authData['code_verifier'] in session

// Handle callback
$tokens = $client->exchangeCode($code, $authData['code_verifier']);
$claims = $client->decodeIdToken($tokens->idToken);
$client->validateClaims($claims, $authData['nonce']);
```

Or use the factory (handles auto-discovery + caching):

```php
use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;

$client = OidcClientFactory::create(
    issuer: 'https://sso.example.com',
    clientId: 'my-app',
    redirectUri: 'https://app.com/callback',
    httpClient: $httpClient,
    requestFactory: $requestFactory,
    streamFactory: $streamFactory,
);
```

## Docker/Kubernetes (Dual-URL)

```yaml
eurip_sso:
    # Internal URL for token exchange (server-to-server)
    issuer: 'http://sso-container:8080'

    # Public URL for browser redirects
    public_issuer: 'https://sso.example.com'
```

## Troubleshooting

Having issues? Check the [Troubleshooting Guide](docs/TROUBLESHOOTING.md) for common problems and solutions:

- Invalid state after login
- Token signature verification failed
- Discovery URL not reachable
- User not found after callback
- Session not persisted

## License

MIT License
