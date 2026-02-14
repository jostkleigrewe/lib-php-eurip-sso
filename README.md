# EURIP SSO Bundle

OIDC Client Library and Symfony Bundle for Single Sign-On.

🇩🇪 [Deutsche Version](README.de.md)

## Features

- **Zero-Code Integration** - Complete OIDC auth via configuration only
- OIDC Authorization Code Flow with PKCE (S256)
- **Device Authorization Grant (RFC 8628)** - For CLI, Smart TV, IoT
- **Client Credentials Flow** - Machine-to-machine authentication
- **Token Introspection (RFC 7662)** - Validate and inspect tokens
- **Session Management** - Detect SSO session changes in real-time
- Auto-Discovery via `.well-known/openid-configuration`
- Dual-URL Support for Docker/Kubernetes environments
- Automatic User Provisioning with Doctrine
- JWT Signature Verification with key rotation resilience
- Extensive Event System (9 events)
- Twig Functions for templates
- PSR-3 Logging, PSR-18 HTTP Client

## Requirements

- PHP 8.4+
- Symfony 7.0+ or 8.0+

## Installation

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

```php
// config/bundles.php
Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
```

## Quick Start

### 1. Configure Bundle

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'

    user_provider:
        enabled: true
        entity: App\Entity\User
        mapping:
            subject: oidcSubject
            issuer: oidcIssuer
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
- `/auth/login` - Start login
- `/auth/callback` - SSO callback
- `/auth/logout` - Logout (POST with CSRF)
- `/auth/profile` - User profile

## Twig Functions

Use SSO data directly in your templates:

```twig
{% if sso_is_authenticated() %}
    Hello {{ sso_name() ?? sso_email() }}!

    {% if sso_has_role('ROLE_ADMIN') %}
        <a href="/admin">Admin Panel</a>
    {% endif %}

    {% if sso_has_permission('users:edit') %}
        <a href="/users">Manage Users</a>
    {% endif %}
{% endif %}
```

### Available Functions

| Function | Description |
|----------|-------------|
| `sso_is_authenticated()` | Check if user is logged in |
| `sso_email()` | User's email address |
| `sso_name()` | User's display name |
| `sso_user_id()` | User's subject (sub claim) |
| `sso_has_role('ROLE_X')` | Check role (global or client) |
| `sso_has_permission('x:y')` | Check permission |
| `sso_has_group('group')` | Check group membership |
| `sso_claim('key', 'default')` | Get any claim value |
| `sso_supports_session_management()` | Check if IdP supports session management |
| `sso_session_management_config(5000)` | Get config for session polling |

### Logout Component

Secure logout with CSRF protection (requires `symfony/ux-twig-component`):

```twig
{# Simple button #}
<twig:EuripSso:Logout />

{# Styled button #}
<twig:EuripSso:Logout label="Sign Out" class="btn btn-danger" />

{# As link #}
<twig:EuripSso:Logout :asLink="true" />

{# With confirmation #}
<twig:EuripSso:Logout confirm="Are you sure?" />
```

### Session Monitor

Detect SSO session changes (logout from other app):

```twig
{% if sso_supports_session_management() %}
    {% include '@EuripSso/components/SessionMonitor.html.twig' %}
{% endif %}
```

## Console Commands

```bash
bin/console eurip:sso:cache-warmup        # Pre-fetch OIDC config + JWKS
bin/console eurip:sso:test-connection     # Test OIDC provider connection
bin/console eurip:sso:device-login        # CLI login via Device Code Flow
bin/console eurip:sso:client-credentials  # Get M2M token (Client Credentials)
bin/console eurip:sso:introspect <token>  # Validate and inspect a token
```

## Device Code Flow (RFC 8628)

For CLI tools, Smart TVs, or IoT devices without a browser:

### CLI Usage

```bash
# Interactive login
bin/console eurip:sso:device-login

# With custom scopes
bin/console eurip:sso:device-login --scopes="openid,profile,roles"

# Output access token for piping
ACCESS_TOKEN=$(bin/console eurip:sso:device-login --output-token)

# Full JSON response
bin/console eurip:sso:device-login --output-json
```

### Programmatic Usage

```php
use Jostkleigrewe\Sso\Client\OidcClient;

// 1. Request device code
$deviceCode = $oidcClient->requestDeviceCode(['openid', 'profile']);

// 2. Show instructions to user
echo "Open: {$deviceCode->verificationUri}\n";
echo "Enter code: {$deviceCode->getFormattedUserCode()}\n";

// 3. Poll for token (blocking)
$tokenResponse = $oidcClient->awaitDeviceToken($deviceCode);
```

## Client Credentials Flow (M2M)

For server-to-server authentication without user interaction:

```bash
# Get access token
bin/console eurip:sso:client-credentials

# With specific scopes
bin/console eurip:sso:client-credentials --scopes="api:read,api:write"

# Output token only (for scripts)
TOKEN=$(bin/console eurip:sso:client-credentials --output-token)
```

```php
// Programmatic usage
$tokenResponse = $oidcClient->requestClientCredentials(['api:read']);
$accessToken = $tokenResponse->accessToken;
```

## Token Introspection (RFC 7662)

Validate and inspect tokens:

```bash
bin/console eurip:sso:introspect "eyJhbG..."
bin/console eurip:sso:introspect "eyJhbG..." --output-json
```

```php
// Programmatic usage
$introspection = $oidcClient->introspectToken($accessToken);

if ($introspection->active) {
    echo "Token valid until: " . $introspection->exp;
    echo "Subject: " . $introspection->sub;
}
```

## Events

Customize the authentication flow with events:

| Event | When |
|-------|------|
| `OidcPreLoginEvent` | Before redirect to IdP |
| `OidcLoginSuccessEvent` | After successful login |
| `OidcLoginFailureEvent` | After failed login |
| `OidcPreLogoutEvent` | Before logout |
| `OidcUserCreatedEvent` | New user provisioned |
| `OidcUserUpdatedEvent` | Existing user updated |
| `OidcTokenRefreshedEvent` | Token refreshed |
| `OidcBackchannelLogoutEvent` | Back-channel logout received |
| `OidcFrontchannelLogoutEvent` | Front-channel logout received |

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;

#[AsEventListener]
public function onLoginSuccess(OidcLoginSuccessEvent $event): void
{
    $user = $event->user;
    $claims = $event->claims;

    // Custom logic after login
}
```

## Docker/Kubernetes

```yaml
eurip_sso:
    issuer: 'http://sso-container:8080'        # Internal URL
    public_issuer: 'https://sso.example.com'   # Public URL
    require_https: false                        # Only for local dev!
```

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/INSTALL.md) | Detailed setup instructions |
| [Configuration](docs/CONFIGURATION.md) | Full configuration reference |
| [Services](docs/SERVICES.md) | Authorization & claims services |
| [Events](docs/EVENTS.md) | Customize authentication flow |
| [Flow Diagrams](docs/FLOW-DIAGRAMS.md) | Visual sequence diagrams for all flows |
| [Device Code Flow](docs/DEVICE-CODE-FLOW.md) | RFC 8628 for CLI, Smart TV, IoT |
| [M2M Authentication](docs/M2M-AUTHENTICATION.md) | Client Credentials & Token Introspection |
| [Session Management](docs/SESSION-MANAGEMENT.md) | Detect SSO session changes |
| [Standalone](docs/STANDALONE.md) | Use without Symfony Bundle |
| [Security](docs/SECURITY.md) | HTTPS, JWT verification, PKCE |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Upgrade Guide](UPGRADE.md) | Breaking changes between versions |

## License

MIT License
