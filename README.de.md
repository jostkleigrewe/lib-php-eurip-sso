# EURIP SSO Bundle

OIDC Client Library und Symfony Bundle für Single Sign-On.

🇬🇧 [English Version](README.md)

## Features

- **Zero-Code Integration** - Komplette OIDC-Authentifizierung nur durch Konfiguration
- OIDC Authorization Code Flow mit PKCE (S256)
- **Device Authorization Grant (RFC 8628)** - Für CLI, Smart TV, IoT
- Auto-Discovery via `.well-known/openid-configuration`
- Dual-URL Support für Docker/Kubernetes-Umgebungen
- Automatische User-Provisionierung mit Doctrine
- JWT-Signaturprüfung mit Key-Rotation-Resilienz
- Umfangreiches Event-System (9 Events)
- PSR-3 Logging, PSR-18 HTTP Client

## Voraussetzungen

- PHP 8.4+
- Symfony 7.0+ oder 8.0+

## Installation

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

```php
// config/bundles.php
Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
```

## Quick Start

### 1. Bundle konfigurieren

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

### 2. Security konfigurieren

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

**Fertig!** Verfügbare Routen:
- `/auth/login` - Login starten
- `/auth/callback` - SSO Callback
- `/auth/logout` - Logout (POST mit CSRF)
- `/auth/profile` - User-Profil

## Dokumentation

| Dokument | Beschreibung |
|----------|--------------|
| [Installationsanleitung](docs/INSTALL.de.md) | Detaillierte Setup-Anleitung |
| [Konfiguration](docs/CONFIGURATION.md) | Vollständige Konfigurationsreferenz |
| [Services](docs/SERVICES.md) | Autorisierung & Claims-Services |
| [Events](docs/EVENTS.md) | Authentifizierungs-Flow anpassen |
| [Device Code Flow](docs/DEVICE-CODE-FLOW.de.md) | RFC 8628 für CLI, Smart TV, IoT |
| [M2M-Authentifizierung](docs/M2M-AUTHENTICATION.de.md) | Client Credentials & Token Introspection |
| [Standalone](docs/STANDALONE.md) | Nutzung ohne Symfony Bundle |
| [Sicherheit](docs/SECURITY.md) | HTTPS, JWT-Prüfung, PKCE |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Häufige Probleme und Lösungen |
| [Upgrade Guide](UPGRADE.md) | Breaking Changes zwischen Versionen |

## Konsolen-Befehle

```bash
bin/console eurip:sso:cache-warmup        # OIDC-Config + JWKS vorladen
bin/console eurip:sso:test-connection     # OIDC-Provider-Verbindung testen
bin/console eurip:sso:device-login        # CLI-Login via Device Code Flow
bin/console eurip:sso:client-credentials  # M2M-Token holen (Client Credentials)
bin/console eurip:sso:introspect <token>  # Token validieren und inspizieren
```

## Device Code Flow (RFC 8628)

Für CLI-Tools, Smart TVs oder IoT-Geräte ohne Browser:

### CLI-Nutzung

```bash
# Interaktiver Login
bin/console eurip:sso:device-login

# Mit eigenen Scopes
bin/console eurip:sso:device-login --scopes="openid,profile,roles"

# Access Token für Pipe ausgeben
ACCESS_TOKEN=$(bin/console eurip:sso:device-login --output-token)

# Volle JSON-Response
bin/console eurip:sso:device-login --output-json
```

### Programmatische Nutzung

```php
use Jostkleigrewe\Sso\Client\OidcClient;

// 1. Device Code anfordern
$deviceCode = $oidcClient->requestDeviceCode(['openid', 'profile']);

// 2. Anweisungen anzeigen
echo "Öffne: {$deviceCode->verificationUri}\n";
echo "Code eingeben: {$deviceCode->getFormattedUserCode()}\n";

// 3. Auf Token warten (blockierend)
$tokenResponse = $oidcClient->awaitDeviceToken($deviceCode);

// Oder manuell pollen
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
    issuer: 'http://sso-container:8080'        # Interne URL
    public_issuer: 'https://sso.example.com'   # Öffentliche URL
    require_https: false                        # Nur für lokale Entwicklung!
```

## Lizenz

MIT License
