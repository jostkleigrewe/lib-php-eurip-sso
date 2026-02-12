# EURIP SSO Bundle

OIDC Client Library and Symfony Bundle for Single Sign-On.

🇩🇪 [Deutsche Version](README.de.md)

## Features

- **Zero-Code Integration** - Complete OIDC auth via configuration only
- OIDC Authorization Code Flow with PKCE (S256)
- **Device Authorization Grant (RFC 8628)** - For CLI, Smart TV, IoT
- Auto-Discovery via `.well-known/openid-configuration`
- Dual-URL Support for Docker/Kubernetes environments
- Automatic User Provisioning with Doctrine
- JWT Signature Verification with key rotation resilience
- Extensive Event System (9 events)
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

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/INSTALL.md) | Detailed setup instructions |
| [Configuration](docs/CONFIGURATION.md) | Full configuration reference |
| [Services](docs/SERVICES.md) | Authorization & claims services |
| [Events](docs/EVENTS.md) | Customize authentication flow |
| [Device Code Flow](docs/DEVICE-CODE-FLOW.md) | RFC 8628 for CLI, Smart TV, IoT |
| [M2M Authentication](docs/M2M-AUTHENTICATION.md) | Client Credentials & Token Introspection |
| [Standalone](docs/STANDALONE.md) | Use without Symfony Bundle |
| [Security](docs/SECURITY.md) | HTTPS, JWT verification, PKCE |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Upgrade Guide](UPGRADE.md) | Breaking changes between versions |

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

// Or poll manually
while (true) {
    $result = $oidcClient->pollDeviceToken($deviceCode->deviceCode);

    if ($result->isSuccess()) {
        $tokenResponse = $result->tokenResponse;
        break;
    }

    if ($result->isError()) {
        throw new \Exception($result->errorDescription);
    }

    sleep($result->getRecommendedInterval($deviceCode->interval));
}
```

## Docker/Kubernetes

```yaml
eurip_sso:
    issuer: 'http://sso-container:8080'        # Internal URL
    public_issuer: 'https://sso.example.com'   # Public URL
    require_https: false                        # Only for local dev!
```

## License

MIT License
