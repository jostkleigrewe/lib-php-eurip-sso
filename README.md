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
- Extensive Event System (6 events)
- PSR-3 Logging, PSR-18 HTTP Client

## Requirements

- PHP 8.2+
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

    controller:
        enabled: true

    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        after_login: /
        profile: /auth/profile    # optional
        debug: /auth/debug        # optional

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
            custom_authenticator: App\Security\NoopAuthenticator
```

**Done!** Routes available:
- `/auth/login` - Start login
- `/auth/callback` - SSO callback
- `/auth/logout` - Logout
- `/auth/profile` - User profile
- `/auth/debug` - OIDC config

## Events

| Event | When | Purpose |
|-------|------|---------|
| `OidcPreLoginEvent` | Before IdP redirect | Modify scopes, cancel |
| `OidcLoginSuccessEvent` | After login | Modify roles, redirect |
| `OidcLoginFailureEvent` | On error | Custom error response |
| `OidcUserCreatedEvent` | New user | Modify before persist |
| `OidcUserUpdatedEvent` | User updated | Modify before flush |
| `OidcPreLogoutEvent` | Before logout | Skip SSO logout |

### Example: Add Role Based on Claims

```php
#[AsEventListener(event: OidcLoginSuccessEvent::NAME)]
class AddAdminRoleListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        if (in_array('admin', $event->claims['groups'] ?? [])) {
            $event->addRole('ROLE_ADMIN');
        }
    }
}
```

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

    controller:
        enabled: false

    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        after_login: /
        after_logout: /
        profile: null
        debug: null
        test: null

    user_provider:
        enabled: false
        entity: null
        mapping:
            subject: oidcSubject
            issuer: oidcIssuer
            email: email
            roles: roles
            external_roles: externalRoles
        claims_sync: {}
        roles_claim: roles
        default_roles: [ROLE_USER]
        sync_on_login: true
        auto_create: true
```

## Standalone Usage

```php
$client = OidcClient::fromDiscovery(
    issuer: 'https://sso.example.com',
    clientId: 'my-app',
    redirectUri: 'https://app.com/callback',
    httpClient: $psrClient,
    requestFactory: $requestFactory,
    streamFactory: $streamFactory,
);

$authData = $client->buildAuthorizationUrl(['openid', 'profile']);
// Redirect to $authData['url']

// Callback
$tokens = $client->exchangeCode($code, $authData['code_verifier']);
$claims = $client->decodeIdToken($tokens->idToken);
$client->validateClaims($claims, $authData['nonce']);
```

## License

MIT License
