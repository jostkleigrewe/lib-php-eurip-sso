# EURIP SSO Bundle

OIDC Client Library und Symfony Bundle für Single Sign-On.

🇬🇧 [English Version](README.md)

## Features

- **Zero-Code Integration** - Komplette OIDC-Authentifizierung nur durch Konfiguration
- OIDC Authorization Code Flow mit PKCE (S256)
- **Device Authorization Grant (RFC 8628)** - Für CLI, Smart TV, IoT
- **Client Credentials Flow** - Machine-to-Machine Authentifizierung
- **Token Introspection (RFC 7662)** - Tokens validieren und inspizieren
- **Session Management** - SSO-Session-Änderungen in Echtzeit erkennen
- Auto-Discovery via `.well-known/openid-configuration`
- Dual-URL Support für Docker/Kubernetes-Umgebungen
- Automatische User-Provisionierung mit Doctrine
- JWT-Signaturprüfung mit Key-Rotation-Resilienz
- Umfangreiches Event-System (9 Events)
- Twig-Funktionen für Templates
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

## Twig-Funktionen

SSO-Daten direkt in Templates verwenden:

```twig
{% if sso_is_authenticated() %}
    Hallo {{ sso_name() ?? sso_email() }}!

    {% if sso_has_role('ROLE_ADMIN') %}
        <a href="/admin">Admin-Bereich</a>
    {% endif %}

    {% if sso_has_permission('users:edit') %}
        <a href="/users">Benutzer verwalten</a>
    {% endif %}
{% endif %}
```

### Verfügbare Funktionen

| Funktion | Beschreibung |
|----------|--------------|
| `sso_is_authenticated()` | Prüft ob User eingeloggt ist |
| `sso_email()` | E-Mail-Adresse des Users |
| `sso_name()` | Anzeigename des Users |
| `sso_user_id()` | Subject des Users (sub Claim) |
| `sso_has_role('ROLE_X')` | Prüft Rolle (global oder Client) |
| `sso_has_permission('x:y')` | Prüft Berechtigung |
| `sso_has_group('group')` | Prüft Gruppenzugehörigkeit |
| `sso_claim('key', 'default')` | Beliebigen Claim-Wert abrufen |
| `sso_supports_session_management()` | Prüft ob IdP Session Management unterstützt |
| `sso_session_management_config(5000)` | Config für Session-Polling |

### Logout-Komponente

Sicherer Logout mit CSRF-Schutz (benötigt `symfony/ux-twig-component`):

```twig
{# Einfacher Button #}
<twig:EuripSso:Logout />

{# Gestylter Button #}
<twig:EuripSso:Logout label="Abmelden" class="btn btn-danger" />

{# Als Link #}
<twig:EuripSso:Logout :asLink="true" />

{# Mit Bestätigung #}
<twig:EuripSso:Logout confirm="Wirklich abmelden?" />
```

### Session Monitor

SSO-Session-Änderungen erkennen (Logout aus anderer App):

```twig
{% if sso_supports_session_management() %}
    {% include '@EuripSso/components/SessionMonitor.html.twig' %}
{% endif %}
```

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
```

## Client Credentials Flow (M2M)

Für Server-zu-Server-Authentifizierung ohne Benutzerinteraktion:

```bash
# Access Token holen
bin/console eurip:sso:client-credentials

# Mit bestimmten Scopes
bin/console eurip:sso:client-credentials --scopes="api:read,api:write"

# Nur Token ausgeben (für Skripte)
TOKEN=$(bin/console eurip:sso:client-credentials --output-token)
```

```php
// Programmatische Nutzung
$tokenResponse = $oidcClient->requestClientCredentials(['api:read']);
$accessToken = $tokenResponse->accessToken;
```

## Token Introspection (RFC 7662)

Tokens validieren und inspizieren:

```bash
bin/console eurip:sso:introspect "eyJhbG..."
bin/console eurip:sso:introspect "eyJhbG..." --output-json
```

```php
// Programmatische Nutzung
$introspection = $oidcClient->introspectToken($accessToken);

if ($introspection->active) {
    echo "Token gültig bis: " . $introspection->exp;
    echo "Subject: " . $introspection->sub;
}
```

## Events

Den Authentifizierungs-Flow mit Events anpassen:

| Event | Wann |
|-------|------|
| `OidcPreLoginEvent` | Vor Weiterleitung zum IdP |
| `OidcLoginSuccessEvent` | Nach erfolgreichem Login |
| `OidcLoginFailureEvent` | Nach fehlgeschlagenem Login |
| `OidcPreLogoutEvent` | Vor Logout |
| `OidcUserCreatedEvent` | Neuer User provisioniert |
| `OidcUserUpdatedEvent` | Bestehender User aktualisiert |
| `OidcTokenRefreshedEvent` | Token erneuert |
| `OidcBackchannelLogoutEvent` | Back-Channel Logout empfangen |
| `OidcFrontchannelLogoutEvent` | Front-Channel Logout empfangen |

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;

#[AsEventListener]
public function onLoginSuccess(OidcLoginSuccessEvent $event): void
{
    $user = $event->user;
    $claims = $event->claims;

    // Eigene Logik nach Login
}
```

## Docker/Kubernetes

```yaml
eurip_sso:
    issuer: 'http://sso-container:8080'        # Interne URL
    public_issuer: 'https://sso.example.com'   # Öffentliche URL
    require_https: false                        # Nur für lokale Entwicklung!
```

## Dokumentation

| Dokument | Beschreibung |
|----------|--------------|
| [Installationsanleitung](docs/INSTALL.de.md) | Detaillierte Setup-Anleitung |
| [Konfiguration](docs/CONFIGURATION.md) | Vollständige Konfigurationsreferenz |
| [Services](docs/SERVICES.md) | Autorisierung & Claims-Services |
| [Events](docs/EVENTS.md) | Authentifizierungs-Flow anpassen |
| [Flow-Diagramme](docs/FLOW-DIAGRAMS.de.md) | Visuelle Sequenzdiagramme für alle Flows |
| [Device Code Flow](docs/DEVICE-CODE-FLOW.de.md) | RFC 8628 für CLI, Smart TV, IoT |
| [M2M-Authentifizierung](docs/M2M-AUTHENTICATION.de.md) | Client Credentials & Token Introspection |
| [Session Management](docs/SESSION-MANAGEMENT.de.md) | SSO-Session-Änderungen erkennen |
| [Standalone](docs/STANDALONE.md) | Nutzung ohne Symfony Bundle |
| [Sicherheit](docs/SECURITY.md) | HTTPS, JWT-Prüfung, PKCE |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Häufige Probleme und Lösungen |
| [Upgrade Guide](UPGRADE.md) | Breaking Changes zwischen Versionen |

## Lizenz

MIT License
