# EURIP SSO Bundle

OIDC Client Library und Symfony Bundle für Single Sign-On.

🇬🇧 [English Version](README.md)

## Features

- **Zero-Code Integration** - Komplette OIDC-Authentifizierung nur durch Konfiguration
- OIDC Authorization Code Flow mit PKCE (S256)
- Auto-Discovery via `.well-known/openid-configuration`
- Dual-URL Support (interne/öffentliche Issuer-URL für Docker/K8s)
- Automatische User-Provisionierung mit Doctrine
- Hybrid User Strategy (SSO-Daten synchronisieren, lokale Daten behalten)
- Umfangreiches Event-System (6 Events)
- PSR-3 Logging, PSR-18 HTTP Client

## Voraussetzungen

- PHP 8.2+
- Symfony 7.0+ oder 8.0+
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

### 1. Bundle konfigurieren

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
            custom_authenticator: App\Security\NoopAuthenticator
```

**Fertig!** Verfügbare Routen:
- `/auth/login` - Login starten
- `/auth/callback` - SSO Callback
- `/auth/logout` - Logout
- `/auth/profile` - User-Profil
- `/auth/debug` - OIDC-Konfiguration

## Hybrid User Strategy

**Vom SSO synchronisiert (bei jedem Login):**
- Email
- External Roles (Gruppen/Rollen aus SSO)
- Weitere Claims (konfigurierbar via `claims_sync`)

**Lokal in der App:**
- App-spezifische Rollen (z.B. ROLE_ADMIN manuell vergeben)
- User Preferences
- App-spezifische Daten

## Events

| Event | Wann | Zweck |
|-------|------|-------|
| `OidcPreLoginEvent` | Vor IdP-Redirect | Scopes ändern, abbrechen |
| `OidcLoginSuccessEvent` | Nach Login | Rollen ändern, Redirect |
| `OidcLoginFailureEvent` | Bei Fehler | Custom Error Response |
| `OidcUserCreatedEvent` | Neuer User | Vor Persist ändern |
| `OidcUserUpdatedEvent` | User aktualisiert | Vor Flush ändern |
| `OidcPreLogoutEvent` | Vor Logout | SSO-Logout überspringen |

### Beispiel: Rolle basierend auf Claims hinzufügen

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

### Beispiel: Willkommens-Mail bei neuen Usern

```php
#[AsEventListener(event: OidcUserCreatedEvent::NAME)]
class WelcomeEmailListener
{
    public function __invoke(OidcUserCreatedEvent $event): void
    {
        $email = $event->claims['email'] ?? null;
        if ($email) {
            // Willkommens-Mail senden
        }
    }
}
```

## Client Services

Das Bundle bietet optionale Client-Services für einfachen Zugriff auf Claims, Berechtigungs-Checks und API-Calls.

### Client Services aktivieren

```yaml
eurip_sso:
    client_services:
        enabled: true
        store_access_token: true
```

### Verfügbare Services

| Service | Alias | Zweck |
|---------|-------|-------|
| `EuripSsoClaimsService` | `eurip_sso.claims` | Zugriff auf ID-Token Claims |
| `EuripSsoAuthorizationService` | `eurip_sso.auth` | Permission/Rollen-Checks |
| `EuripSsoApiClient` | `eurip_sso.api` | API-Calls zum SSO Server |
| `EuripSsoTokenStorage` | `eurip_sso.token_storage` | Token-Speicher-Zugriff |
| `EuripSsoFacade` | `eurip_sso.facade` | Kombiniert alle Services |

### Nutzungsbeispiele

```php
// Direkte Service-Injection
public function __construct(
    private readonly EuripSsoAuthorizationService $auth,
    private readonly EuripSsoClaimsService $claims,
) {}

public function edit(): Response
{
    // Permission erfordern (wirft PermissionDeniedException wenn fehlend)
    $this->auth->requirePermission('edit:article');

    // Claims abrufen
    $email = $this->claims->getEmail();
    $userId = $this->claims->getUserId();
    $roles = $this->claims->getClientRoles();

    // Permissions prüfen
    if ($this->auth->hasPermission('delete:article')) {
        // ...
    }
}

// Oder mit Facade
public function __construct(private readonly EuripSsoFacade $sso) {}

public function index(): Response
{
    $email = $this->sso->getEmail();
    $isAdmin = $this->sso->hasRole('ROLE_ADMIN');

    // Auf verschachtelte Services zugreifen
    $userInfo = $this->sso->api()->getUserInfo();
    $allClaims = $this->sso->claims()->all();
}
```

### Authorization-Methoden

```php
// Check-Methoden (return bool)
$auth->hasRole('ROLE_ADMIN');
$auth->hasClientRole('editor');
$auth->hasPermission('edit:article');
$auth->hasAnyPermission(['edit:article', 'delete:article']);
$auth->hasAllPermissions(['view:article', 'edit:article']);
$auth->isInGroup('editors');
$auth->canAccess();  // Nicht blockiert

// Require-Methoden (werfen PermissionDeniedException)
$auth->requireRole('ROLE_ADMIN');
$auth->requirePermission('edit:article');
$auth->requireAccess();
```

### Claims-Zugriff

```php
// Standard-Claims
$claims->getEmail();
$claims->getName();
$claims->getUserId();  // Subject
$claims->getLocale();

// Client-spezifische Claims (EURIP SSO)
$claims->getRoles();            // Globale Rollen
$claims->getClientRoles();      // Client-spezifische Rollen
$claims->getClientPermissions();
$claims->getClientGroups();
$claims->isBlocked();

// Generischer Zugriff
$claims->get('custom_claim', 'default');
$claims->all();  // Alle Claims als Array
```

## Konfigurationsreferenz

```yaml
eurip_sso:
    # Erforderlich
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'

    # Optional
    client_secret: null
    public_issuer: null              # Für Docker/K8s
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

    client_services:
        enabled: false
        store_access_token: true
```

## Docker/Kubernetes (Dual-URL)

```yaml
eurip_sso:
    # Interne URL für Token-Exchange (Server-zu-Server)
    issuer: 'http://sso-container:8080'

    # Öffentliche URL für Browser-Redirects
    public_issuer: 'https://sso.example.com'
```

## Migration von eigener Implementierung

### Vorher (~600 Zeilen Code)

```
src/
├── Controller/AuthController.php
├── Security/
│   ├── AppUserProvider.php
│   ├── JwtValidator.php
│   └── LoginStateStorage.php
└── OAuth/
    ├── OidcTokenClient.php
    └── OidcDiscoveryClient.php
```

### Nachher (~30 Zeilen Config)

```
config/packages/eurip_sso.yaml
```

### Migrations-Schritte

1. Bundle konfigurieren mit `controller.enabled: true` und `user_provider.enabled: true`
2. Security.yaml: Provider auf `DoctrineOidcUserProvider` ändern
3. Alte Dateien entfernen
4. Event Listener für Custom-Logik hinzufügen (optional)

## Standalone Usage (ohne Bundle)

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
// Redirect zu $authData['url']

// Callback
$tokens = $client->exchangeCode($code, $authData['code_verifier']);
$claims = $client->decodeIdToken($tokens->idToken);
$client->validateClaims($claims, $authData['nonce']);
```

## Lizenz

MIT License
