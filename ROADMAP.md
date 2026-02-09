# ROADMAP: OIDC Auth Bundle

> Zuletzt aktualisiert: 2026-02-09

---

## 🎯 Aktueller Stand

**Letzte Aktivität:** Dokumentation aktualisiert (README.md, README.de.md, CHANGELOG.md)

**Nächster Schritt:** Alle Phasen abgeschlossen. Dokumentation aktuell. Optionale Features verfügbar.

**Blockiert durch:** Nichts

**Offene Fragen:** Keine

---

## 📊 Projekt-Status

```
Gesamtfortschritt: ████████████████████████ 100% ✅

Phase 1 (Bug-Fixes):       ████████████████████████ 100% ✅
Phase 2 (Auth + Bundle):   ████████████████████████ 100% ✅
Phase 3 (Code-Bereinigung):████████████████████████ 100% ✅
Phase 4 (JWT + Tests):     ████████████████████████ 100% ✅
```

> Feature-Phasen 1-12 abgeschlossen: siehe [ROADMAP-ARCHIV.md](ROADMAP-ARCHIV.md)

---

## 🔴 Phase 1: Bug-Fixes (Quick Wins) ✅ ABGESCHLOSSEN

> Ziel: Sofort wirksame Korrekturen ohne Risiko
> **Status: 2/2 Tasks erledigt**

### 1.1 Cache-Key im Warmup-Command fixen ✅
- [x] Statische Methode `OidcClientFactory::buildJwksCacheKey(string $jwksUri): string` extrahiert
- [x] `OidcCacheWarmupCommand.php`: Shared Methode nutzt
- [x] `OidcClientFactory::preloadJwks()`: Shared Methode nutzt
- **Erledigt:** 2026-02-08
- **Geänderte Dateien:**
  - `src/Bundle/Factory/OidcClientFactory.php` — `buildJwksCacheKey()` public static + `preloadJwks()` nutzt sie
  - `src/Bundle/Command/OidcCacheWarmupCommand.php` — nutzt `OidcClientFactory::buildJwksCacheKey()`

### 1.2 TokenExchangeFailedException: sprintf() ✅
- [x] `sprintf('Token exchange failed: %s - %s', ...)` statt String-Interpolation
- **Erledigt:** 2026-02-08
- **Geänderte Dateien:**
  - `src/Contracts/Exception/TokenExchangeFailedException.php`

---

## 🔴 Phase 2: Auth-Architektur + Bundle modernisieren ✅ ABGESCHLOSSEN

> Ziel: OidcAuthenticator modernisieren, Bundle-Config und Service-Registrierung drastisch vereinfachen.
> **Status: 7/7 Tasks erledigt**

### 2.1 OidcAuthenticationException erstellen ✅
- [x] Neue Klasse `src/Contracts/Exception/OidcAuthenticationException.php`
- **Erledigt:** 2026-02-08

### 2.2 OidcAuthenticator modernisieren ✅
- [x] Delegiert an `OidcAuthenticationService`, nutzt `OidcAuthenticationException`
- **Erledigt:** 2026-02-08

### 2.3 AuthenticationController::callback() → LogicException-Fallback ✅
- [x] `callback()` wirft `LogicException`, Return-Type `never`
- **Erledigt:** 2026-02-08

### 2.4 Bundle-Config vereinfachen ✅
- [x] `client_services.enabled`, `controller.enabled` entfernt, `authenticator` reduziert
- **Erledigt:** 2026-02-08

### 2.5 Authenticator Service-Registrierung ✅
- [x] Bedingt in `loadExtension()`, `#[Autowire]` für skalare Params
- **Erledigt:** 2026-02-08

### 2.6 Service-Registrierung modernisieren ✅
- [x] Resource-Scanning, `#[Autowire]`, EuripSsoBundle von 528 auf ~280 Zeilen
- **Erledigt:** 2026-02-08

### 2.7 Authenticator-Config Parameter-Mapping ✅
- [x] Alle `#[Autowire]` auf `routes.*` umgestellt
- **Erledigt:** 2026-02-08

---

## 🟡 Phase 3: Code-Bereinigung ✅ ABGESCHLOSSEN

> Ziel: Duplizierung entfernen, Patterns vereinheitlichen, toten Code entfernen
> **Status: 7/7 Tasks erledigt**

### 3.1 DoctrineOidcUserProvider: Entduplizierung ✅
- [x] `buildRoles(object $entity): array` extrahiert, `createOidcUser()` entfernt
- [x] `wrapUser()` gibt immer `OidcUser` zurück (konsistent)
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - `src/Bundle/Security/DoctrineOidcUserProvider.php`

### 3.2 DoctrineOidcUserProvider: Stille Catches → Logging ✅
- [x] `catch (\Throwable $e)` → `$this->logger?->debug(...)` mit Entity-Klasse und Fehlermeldung
- **Erledigt:** 2026-02-09

### 3.3 DoctrineOidcUserProvider: getEntityId() robuster ✅
- [x] Explizite Prüfung auf empty/null/false, Composite-Key-Warning geloggt
- **Erledigt:** 2026-02-09

### 3.4 OidcConstants: Interface → final class + aufräumen ✅
- [x] `interface` → `final class` mit `private function __construct()`
- [x] Typed Constants (PHP 8.3+): `public const string`, `public const array`
- [x] 9 `EVENT_*`-Constants entfernt
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - `src/Bundle/OidcConstants.php`

### 3.5 Event-Dispatch modernisieren ✅
- [x] `NAME`-Constants aus allen 9 Event-Klassen entfernt
- [x] Alle 10 `dispatch($event, STRING)` Calls → `dispatch($event)` (klassen-basiert)
- [x] `use OidcConstants` Import aus Events und EuripSsoApiClient entfernt
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - 9 Event-Klassen, `OidcAuthenticationService`, `EuripSsoApiClient`, `DoctrineOidcUserProvider`, `BackchannelLogoutController`, `FrontchannelLogoutController`

### 3.6 EuripSsoFacade entfernen + ID-Token-Verifikation ✅
- [x] `EuripSsoFacade.php` gelöscht
- [x] `EuripSsoTwigExtension`: direkt `EuripSsoClaimsService` + `EuripSsoAuthorizationService`
- [x] `EuripSsoApiClient::refreshClaims()`: `verifySignature: true`
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - `src/Bundle/Service/EuripSsoFacade.php` — gelöscht
  - `src/Bundle/Twig/EuripSsoTwigExtension.php` — direkte Service-Injection
  - `src/Bundle/Service/EuripSsoApiClient.php` — ID-Token-Verifikation

### 3.7 RouteLoader entfernen → #[Route]-Attribute ✅
- [x] `OidcRouteLoader.php` + `Routing/`-Verzeichnis gelöscht
- [x] `#[Route]`-Attribute auf allen Controller-Methoden mit `%eurip_sso.routes.*%`
- [x] Diagnostics-Defaults auf nicht-null geändert (immer aktiv, Firewall schützt)
- [x] Logout-Channel Controller weiterhin bedingt entfernt
- [x] Route-Constants in `OidcConstants` beibehalten
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - `src/Bundle/Routing/OidcRouteLoader.php` — gelöscht
  - `src/Bundle/EuripSsoBundle.php` — `registerRouteLoader()` entfernt
  - `config/services.yaml` — `Routing/`-Exclusion entfernt
  - Alle 5 Controller — `#[Route]`-Attribute hinzugefügt

---

## 🟡 Phase 4: JWT-Extraktion + Tests

> Ziel: Crypto-Code in eigenen Service extrahieren, mit RSA-Tests absichern
> **Status: 2/2 Tasks erledigt**

### 4.1 JwtVerifier extrahieren ✅
- [x] Neue Klasse `src/Client/JwtVerifier.php` (frameworkunabhängig)
- [x] Methoden aus `OidcClient` verschieben: `verifySignature()`, `jwkToPublicKey()`, `fetchJwks()`, `findKey()`, etc.
- [x] JWKS Key-Rotation-Resilience: Cache invalidieren → neu laden → 1x Retry
- [x] `OidcClient`: Constructor erhält `JwtVerifier`, `decodeIdToken()` delegiert
- [x] `OidcClientFactory`: `JwtVerifier` erzeugen und an `OidcClient` übergeben
- [x] `OidcCacheWarmupCommand`: `JwtVerifier` direkt injecten, redundanten in-memory Check entfernt
- [x] `EuripSsoBundle`: `JwtVerifier` Service via Factory-Method von `OidcClient::getJwtVerifier()`
- [x] `phpunit.xml.dist`: Bootstrap auf `vendor/autoload.php` geändert (eigener Autoloader statt Parent)
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - `src/Client/JwtVerifier.php` — Neue Klasse mit Crypto/JWKS-Logik + Key-Rotation-Retry
  - `src/Client/OidcClient.php` — JwtVerifier injiziert, Crypto-Code entfernt, `getJwtVerifier()` hinzugefügt
  - `src/Bundle/Factory/OidcClientFactory.php` — Erzeugt JwtVerifier, übergibt an OidcClient
  - `src/Bundle/Command/OidcCacheWarmupCommand.php` — JwtVerifier direkt injiziert
  - `src/Bundle/EuripSsoBundle.php` — JwtVerifier Service registriert
  - `tests/Client/OidcClientTest.php` — Angepasst an neuen Constructor
  - `phpunit.xml.dist` — Bootstrap-Pfad korrigiert

### 4.2 JwtVerifier-Tests mit echtem RSA-Key ✅
- [x] Test-RSA-Key-Pair generieren (2048-bit, in setUp() dynamisch)
- [x] Test: Gültige RS256-Signatur → Verifikation erfolgreich (2 Tests: mit/ohne kid)
- [x] Test: Falsche Signatur → `OidcProtocolException` (2 Tests: falsche Signatur + manipulierte Daten)
- [x] Test: Unbekannter `kid` → Exception (mit HTTP-Mock für Retry)
- [x] Test: Nicht-unterstützter Algorithmus (HS256) → Exception (2 Tests: HS256 + fehlend)
- [x] Test: Key-Rotation-Retry erfolgreich (+ Test: Retry fehlgeschlagen)
- [x] Test: JWKS-Cache-TTL abgelaufen → neu geladen (+ Test: Cache noch frisch)
- [x] Tests: preloadJwks Validierung, hasJwksLoaded, invalidateJwksCache
- **Erledigt:** 2026-02-09
- **Geänderte Dateien:**
  - `tests/Client/JwtVerifierTest.php` — 15 Tests mit echtem RSA-Key-Pair

---

## Offene Features (Optional)

> Nicht blockierend. Bei Bedarf implementieren.

### Dokumentation

| ID | Feature | Priorität | Status |
|----|---------|-----------|--------|
| D.2 | Sequenzdiagramme (Mermaid) | 🟢 Nice-to-have | ⏳ |

### Testing

| ID | Feature | Priorität | Status |
|----|---------|-----------|--------|
| T.1 | E2E-Tests mit Mock-IdP | ⏭️ Geparkt | ⏳ |
| T.2 | Performance-Tests | 🔵 Bei Bedarf | ⏳ |

### Features

| ID | Feature | Priorität | Status |
|----|---------|-----------|--------|
| F.1 | Rate Limiting built-in | 🟢 Nice-to-have | ⏳ |
| F.2 | Token Refresh Event | 🔵 Bei Bedarf | ⏳ |
| F.4 | Device Code Flow | 🔵 Bei Bedarf | ⏳ |
| F.5 | Client Credentials Flow | 🔵 Bei Bedarf | ⏳ |
| F.6 | Token Introspection | 🔵 Bei Bedarf | ⏳ |
| F.7 | Session Management (RP-Initiated) | 🟢 Nice-to-have | ⏳ |
| 13 | Maker Bundle | ⏭️ Geparkt | ⏳ |

---

## Quick Reference

### Console Commands

```bash
# Cache aufwärmen
bin/console eurip:sso:cache:warmup

# Verbindung testen
bin/console eurip:sso:test-connection
```

### Twig-Funktionen

```twig
{{ sso_is_authenticated() }}
{{ sso_email() }}
{{ sso_name() }}
{{ sso_user_id() }}
{{ sso_has_role('ROLE_ADMIN') }}
{{ sso_has_permission('users:edit') }}
{{ sso_has_group('developers') }}
{{ sso_claim('custom', 'default') }}
```

### Minimal-Konfiguration (nach Refactoring)

```yaml
eurip_sso:
    issuer: '%env(SSO_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'
```

---

## Geplante Breaking Changes (nächste Version)

> Checkliste für Client-Anpassungen nach Bundle-Update.

### Konfiguration

| Entfernt | Migration |
|----------|-----------|
| `controller.enabled` | Weg — Controller immer registriert |
| `client_services.enabled` | Weg — Services immer registriert |
| `authenticator.callback_route` | Weg — nutzt `routes.callback` |
| `authenticator.login_path` | Weg — nutzt `routes.login` |
| `authenticator.default_target_path` | Weg — nutzt `routes.after_login` |

**Neue Minimal-Config:** Nur `issuer`, `client_id`, `redirect_uri` nötig. Alles andere hat sinnvolle Defaults.

### Service-Aliase entfernt

| Entfernt | Migration |
|----------|-----------|
| `eurip_sso.facade` | Type-Hint `EuripSsoClaimsService` etc. direkt |
| `eurip_sso.claims` | Type-Hint `EuripSsoClaimsService` |
| `eurip_sso.auth` | Type-Hint `EuripSsoAuthorizationService` |
| `eurip_sso.api` | Type-Hint `EuripSsoApiClient` |
| `eurip_sso.token_storage` | Type-Hint `EuripSsoTokenStorage` |

### EuripSsoFacade: komplett entfernt

| Vorher | Nachher |
|--------|---------|
| `$facade->isAuthenticated()` | `$claimsService->isAuthenticated()` |
| `$facade->getEmail()` | `$claimsService->getEmail()` |
| `$facade->getUserId()` | `$claimsService->getUserId()` |
| `$facade->claims()` | Direkt `EuripSsoClaimsService` injecten |
| `$facade->auth()` | Direkt `EuripSsoAuthorizationService` injecten |
| `$facade->api()` | Direkt `EuripSsoApiClient` injecten |
| `$facade->tokens()` | Direkt `EuripSsoTokenStorage` injecten |

**Prüfen:** `grep -rn "EuripSsoFacade\|eurip_sso\.facade" src/ templates/`

### OidcConstants: Interface → final class

| Vorher | Nachher |
|--------|---------|
| `interface OidcConstants` | `final class OidcConstants` |
| `class Foo implements OidcConstants` | `OidcConstants::SESSION_STATE` direkt nutzen |
| `OidcConstants::EVENT_*` | Entfernt — Event-Klasse ist der Identifier |

**Prüfen:** `grep -r "implements OidcConstants" src/`

### Event-Dispatch: String → Klassen-basiert

| Vorher | Nachher |
|--------|---------|
| `$dispatcher->dispatch($event, OidcConstants::EVENT_LOGIN_SUCCESS)` | `$dispatcher->dispatch($event)` |
| `OidcLoginSuccessEvent::NAME` | Entfernt — nicht mehr nötig |
| Listener auf `'eurip_sso.login.success'` | Listener auf `OidcLoginSuccessEvent::class` |

**Prüfen:** `grep -rn "EVENT_\|::NAME" src/` und Event-Subscriber in der Host-App

### Routing: OidcRouteLoader → #[Route]-Attribute

| Vorher | Nachher |
|--------|---------|
| `routing.yaml`: `resource: . type: eurip_sso` | Controller-Attribute automatisch erkannt |
| Pfade konfigurierbar via RouteLoader | Pfade konfigurierbar via `%eurip_sso.routes.*%` Parameter |

**Prüfen:** `routing.yaml` der Host-App anpassen

### AuthenticationController: callback() → LogicException

| Vorher | Nachher |
|--------|---------|
| `callback()` verarbeitet OIDC Response | `callback()` wirft `LogicException` (Authenticator greift vorher) |
| `login()`, `logout()`, `logoutConfirm()` | Bleiben unverändert |

### OidcAuthenticator: Neues Interface

| Vorher | Nachher |
|--------|---------|
| Eigene Session-Zugriffe, eigene Token-Validierung | Delegiert an `OidcAuthenticationService` |
| Constructor: `OidcClient`, `OidcUserProviderInterface` | Constructor: `OidcAuthenticationService`, `OidcSessionStorage`, ... |

**Prüfen:** Falls die App den Authenticator dekoriert oder extended — an neue Signatur anpassen.

### OidcClient: Constructor geändert

| Vorher | Nachher |
|--------|---------|
| Crypto-Methoden direkt in `OidcClient` | Delegiert an `JwtVerifier` |
| `new OidcClient($config, $httpClient, $cache)` | `new OidcClient($config, $httpClient, $cache, $jwtVerifier)` |

**Prüfen:** Falls `OidcClient` manuell instanziiert wird — `JwtVerifier` ergänzen. `OidcClientFactory` erledigt das automatisch.

### Twig-Funktionen + ID-Token-Verifikation

**Keine Client-Änderung nötig** — Twig-Funktionen bleiben identisch, ID-Token-Verifikation nach Refresh ist internes Sicherheits-Upgrade.
