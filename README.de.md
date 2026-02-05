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
- Umfangreiches Event-System (7 Events)
- PSR-3 Logging, PSR-18 HTTP Client
- **Sicherheit**: JWT-Signaturprüfung, timing-safe Vergleiche, Open-Redirect-Schutz

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

## Erweiterung via Events

Das Bundle dispatcht Events an wichtigen Stellen im Authentifizierungs-Flow und ermöglicht so Anpassungen ohne Bundle-Code zu ändern.

### Event-Übersicht

| Event | Wann | Verfügbare Methoden |
|-------|------|---------------------|
| `OidcPreLoginEvent` | Vor IdP-Redirect | `setScopes()`, `setResponse()` |
| `OidcLoginSuccessEvent` | Nach erfolgreichem Login | `addRole()`, `removeRole()`, `setTargetPath()`, `setResponse()` |
| `OidcLoginFailureEvent` | Bei Auth-Fehler | `setResponse()` |
| `OidcUserCreatedEvent` | Neuer User erstellt | Zugriff auf `$entity`, `$claims` |
| `OidcUserUpdatedEvent` | User synchronisiert | Zugriff auf `$entity`, `$claims` |
| `OidcPreLogoutEvent` | Vor Logout | `skipSsoLogout()`, `setResponse()` |
| `OidcTokenRefreshedEvent` | Nach Token-Refresh | Zugriff auf `$tokenResponse` |

### Häufige Anwendungsfälle

#### Rollen basierend auf Claims hinzufügen

```php
#[AsEventListener(event: OidcLoginSuccessEvent::NAME)]
class AddAdminRoleListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // ROLE_ADMIN hinzufügen wenn User in 'admins' Gruppe
        if (in_array('admins', $event->claims['groups'] ?? [])) {
            $event->addRole('ROLE_ADMIN');
        }
    }
}
```

#### User basierend auf Claims blockieren

```php
#[AsEventListener(event: OidcLoginSuccessEvent::NAME)]
class BlockInactiveUserListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        if ($event->claims['is_blocked'] ?? false) {
            $event->setResponse(new Response('Account gesperrt', 403));
        }
    }
}
```

#### Custom Redirect nach Login

```php
#[AsEventListener(event: OidcLoginSuccessEvent::NAME)]
class RedirectNewUserListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // Neue User zum Onboarding weiterleiten
        if (empty($event->claims['profile_complete'])) {
            $event->setTargetPath('/onboarding');
        }
    }
}
```

#### Willkommens-Mail senden

```php
#[AsEventListener(event: OidcUserCreatedEvent::NAME)]
class WelcomeEmailListener
{
    public function __construct(private MailerInterface $mailer) {}

    public function __invoke(OidcUserCreatedEvent $event): void
    {
        $email = $event->claims['email'] ?? null;
        if ($email) {
            // Willkommens-Mail queuen (Entity noch nicht geflusht!)
            $this->mailer->send(new WelcomeEmail($email));
        }
    }
}
```

#### Zusätzliche Scopes anfordern

```php
#[AsEventListener(event: OidcPreLoginEvent::NAME)]
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

#### SSO-Logout überspringen (nur lokal)

```php
#[AsEventListener(event: OidcPreLogoutEvent::NAME)]
class LocalLogoutOnlyListener
{
    public function __invoke(OidcPreLogoutEvent $event): void
    {
        // Nur lokale Session invalidieren, nicht zum SSO-Logout weiterleiten
        $event->skipSsoLogout();
    }
}
```

#### Custom Error-Seite

```php
#[AsEventListener(event: OidcLoginFailureEvent::NAME)]
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

### Event-Flow Diagramm

```
Login-Flow:
  ┌─────────────────┐
  │ OidcPreLoginEvent │ → Kann Scopes ändern oder abbrechen
  └────────┬────────┘
           ↓
  [Redirect zum IdP]
           ↓
  [User authentifiziert sich]
           ↓
  [Callback empfangen]
           ↓
  ┌─────────────────────┐
  │ OidcUserCreatedEvent │ → Nur für neue User (vor Flush)
  │   ODER               │
  │ OidcUserUpdatedEvent │ → Für bestehende User (vor Flush)
  └────────┬─────────────┘
           ↓
  ┌──────────────────────┐
  │ OidcLoginSuccessEvent │ → Rollen ändern, Redirect, oder blockieren
  └────────┬─────────────┘
           ↓
  [User eingeloggt]

Logout-Flow:
  ┌──────────────────┐
  │ OidcPreLogoutEvent │ → Kann SSO-Logout überspringen oder abbrechen
  └────────┬─────────┘
           ↓
  [Session invalidiert]
           ↓
  [Redirect zu SSO-Logout oder after_logout Pfad]
```

## User-Strategie: Bundle vs. Eigene Entity

Das Bundle stellt `OidcUser` bereit, eine generische User-Klasse. Je nach Anwendungsfall kann diese direkt verwendet oder eine eigene Doctrine Entity erstellt werden.

### Wann die Bundle-OidcUser reicht (Keine eigene Entity)

Die eingebaute `OidcUser` Klasse verwenden wenn:

- **Stateless/API-only** - Keine lokalen User-Daten nötig
- **Einfache Apps** - Nur Authentifizierung, keine User-Verwaltung
- **Microservices** - User-Daten liegen in anderem Service

```yaml
eurip_sso:
    user_provider:
        enabled: false  # Doctrine Provider nicht verwenden
```

`OidcUser` wird bei jedem Login aus Claims erstellt - keine Datenbank nötig.

### Wann eine eigene Entity nötig ist

Eigene User Entity erstellen wenn:

| Anforderung | Beispiel |
|-------------|----------|
| **Lokale Daten** | User-Einstellungen, Präferenzen, Avatar |
| **Lokale Rollen** | ROLE_ADMIN manuell in App vergeben |
| **Relationen** | User hat Bestellungen, Posts, Kommentare |
| **User-Verwaltung** | Admin-Panel zum Auflisten/Bearbeiten |
| **Audit-Trail** | User-Aktivitäten in DB tracken |

```php
// src/Entity/User.php
#[ORM\Entity]
class User implements UserInterface
{
    #[ORM\Column(length: 255)]
    private ?string $oidcSubject = null;

    #[ORM\Column(length: 255)]
    private ?string $oidcIssuer = null;

    // Lokale Daten (nicht vom SSO synchronisiert)
    #[ORM\Column(type: 'json')]
    private array $roles = ['ROLE_USER'];

    // SSO-Daten (bei jedem Login synchronisiert)
    #[ORM\Column(type: 'json')]
    private array $externalRoles = [];

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $email = null;

    // App-spezifische Felder
    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $preferences = null;

    // ... Getter/Setter
}
```

### Hybride Rollen-Strategie

Wenn beide Felder (`roles` und `external_roles`) gemappt sind, werden Rollen **zusammengeführt**:

```yaml
user_provider:
    mapping:
        roles: roles              # Lokale Rollen (bleiben erhalten)
        external_roles: externalRoles  # SSO-Rollen (synchronisiert)
```

- **Lokale Rollen**: Manuell in der App gesetzt (z.B. ROLE_ADMIN)
- **Externe Rollen**: Bei jedem Login vom SSO synchronisiert
- **Effektive Rollen**: Vereinigung beider (lokal + extern)

### Entscheidungsmatrix

| Szenario | Lösung |
|----------|--------|
| API Gateway, kein lokaler State | `OidcUser` (keine Entity) |
| Einfache Web-App, nur Login | `OidcUser` mit `user_provider.enabled: true` |
| Lokale Einstellungen nötig | Eigene Entity |
| Lokale + SSO-Rollen | Eigene Entity mit Hybrid-Mapping |
| Volle User-Verwaltung | Eigene Entity mit `UserInterface` |

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

    # Legacy Authenticator (für eigene Controller-Implementierungen)
    authenticator:
        callback_route: /auth/callback
        default_target_path: /
        login_path: /login
        verify_signature: true       # JWT-Signaturprüfung (empfohlen!)

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
            subject: oidcSubject     # Erforderlich: OIDC Subject Identifier
            issuer: oidcIssuer       # Erforderlich: OIDC Issuer
            email: null              # Optional: E-Mail-Feld
            roles: null              # Optional: Lokale Rollen
            external_roles: null     # Optional: SSO-Rollen
        claims_sync: {}              # Zusätzliches Claim-zu-Feld Mapping
        roles_claim: roles           # Claim-Name für Rollen
        default_roles: [ROLE_USER]
        sync_on_login: true
        auto_create: true

    client_services:
        enabled: false
        store_access_token: true
```

Siehe `config/eurip_sso.yaml.dist` für eine vollständige Beispielkonfiguration.

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
