# ROADMAP: OIDC Auth Bundle - Zero-Code Integration

> Zuletzt aktualisiert: 2026-02-05

## Vision

Eine App-Integration, die nur aus **Konfiguration** besteht - keine Controller, keine Provider, keine Handler.

```yaml
# Ziel-Konfiguration (config/packages/eurip_sso.yaml)
eurip_sso:
    issuer: '%env(SSO_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'

    user_provider:
        entity: App\Entity\User
        mapping:
            subject: oidcSubject
            issuer: oidcIssuer
            email: email
        sync_on_login: true      # Hybrid: Claims bei jedem Login synchronisieren
        auto_create: true

    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
```

---

## Gewählte Strategie: Hybrid

- **Vom SSO synchronisiert (bei jedem Login):**
  - Email
  - External Roles (Gruppen/Rollen aus SSO)
  - Name, Picture, etc. (optional)

- **Lokal in der App:**
  - App-spezifische Rollen (z.B. ROLE_ADMIN manuell vergeben)
  - User Preferences
  - App-spezifische Daten

---

## Status: Feature-Complete

**Bundle ist feature-complete!** ✅

| Komponente | Status |
|------------|--------|
| OidcClient (Core) | ✅ |
| Discovery Caching | ✅ |
| Dual-URL Support | ✅ |
| Claims Validation | ✅ |
| Token Exchange | ✅ |
| Events (9 Events) | ✅ |
| Auth Controllers | ✅ |
| Auth Service | ✅ |
| User Provisioning | ✅ |
| OidcUser | ✅ |
| Security Hardening | ✅ |
| Back-Channel Logout | ✅ |
| Front-Channel Logout | ✅ |
| Tests (41 Tests) | ✅ |
| PHPStan Level 8 | ✅ |

> Phase 1-12 und Bugfixes: erledigt (siehe [ROADMAP-ARCHIV.md](ROADMAP-ARCHIV.md))

---

## Zusammenfassung

| Phase | Beschreibung | Status |
|-------|--------------|--------|
| 1 | Bundle-Routen & Controller | ✅ |
| 2 | State/Session Management | ✅ |
| 3 | Auto User-Provisionierung | ✅ |
| 4 | Generische OidcUser | ✅ |
| 5 | JWT-Duplikate entfernen (~1320 Zeilen) | ✅ |
| 6 | Events erweitern (6 Events) | ✅ |
| 7 | Cleanup & Dokumentation | ✅ |
| 8 | Security Hardening 🔴 | ✅ |
| 9 | Architecture Refactoring | ✅ |
| 10 | Error Handling & Resilience | ✅ |
| 11 | Performance & Optimization | ✅ |
| 12 | Code Quality & Testing | ✅ |
| 13 | Maker Bundle (optional) | ⏭️ |

---

## Zukünftige Verbesserungen (Optional)

> Diese Features sind **nicht blockierend** für Production-Einsatz.
> Sie können bei Bedarf implementiert werden.

### Dokumentation

| ID | Feature | Aufwand | Priorität | Status |
|----|---------|---------|-----------|--------|
| D.1 | Troubleshooting-Guide | 2h | 🟡 Empfohlen | ✅ |
| D.2 | Sequenzdiagramme (Mermaid) | 1h | 🟢 Nice-to-have | ⏳ |

### Testing

| ID | Feature | Aufwand | Priorität |
|----|---------|---------|-----------|
| T.1 | E2E-Tests mit Mock-IdP | 4h | 🟡 Empfohlen |
| T.2 | Performance-Tests | 4h | 🔵 Bei Bedarf |

### Features

| ID | Feature | Aufwand | Priorität | Provider | Status |
|----|---------|---------|-----------|----------|--------|
| F.1 | Rate Limiting built-in | 2h | 🟢 Nice-to-have | - | ⏳ |
| F.2 | Token Refresh Event | 1h | 🔵 Bei Bedarf | - | ⏳ |
| F.3 | Backchannel Logout | 4h | 🟡 Enterprise | ✅ Ready | ✅ |
| F.4 | Device Code Flow | 6h | 🔵 Bei Bedarf | - | ⏳ |
| F.5 | Client Credentials | 3h | 🔵 Bei Bedarf | - | ⏳ |
| F.6 | Token Introspection | 2h | 🔵 Bei Bedarf | - | ⏳ |
| F.7 | Session Management | 4-6h | 🟢 Nice-to-have | ✅ Ready | ⏳ |
| F.8 | Front-Channel Logout | 2h | 🟢 Nice-to-have | ✅ Ready | ✅ |

### Externe Anforderungen (aus Test-App)

> Diese Anforderungen wurden bei der Integration in eine Test-App identifiziert.
> Sie verbessern die Developer Experience, sind aber nicht blockierend.

| ID | Feature | Aufwand | Priorität | Status |
|----|---------|---------|-----------|--------|
| E.1 | Twig-Extension | 2h | 🟡 HOCH | ⏳ |
| E.2 | test-connection Command | 1h | 🟢 NORMAL | ⏳ |
| E.3 | ProfileController Template | 1h | 🟢 NORMAL | ⏳ |

#### E.1 Twig-Extension
- Erstellen: `src/Bundle/Twig/EuripSsoTwigExtension.php`
- Funktionen:
  - `sso_email()` → Email des eingeloggten Users
  - `sso_name()` → Name des Users
  - `sso_user_id()` → Subject
  - `sso_is_authenticated()` → bool
  - `sso_has_role(role)` → bool
  - `sso_has_permission(permission)` → bool
  - `sso_has_group(group)` → bool
  - `sso_claim(name, default)` → mixed
- Registrierung: Bedingt wenn `client_services.enabled: true`

#### E.2 Console Command: test-connection
- Command: `bin/console eurip:sso:test-connection`
- Prüft:
  - Discovery Endpoint erreichbar (+ Latenz)
  - JWKS Endpoint erreichbar (+ Latenz)
  - Token Endpoint erreichbar (ohne Auth, nur Ping)
  - UserInfo Endpoint erreichbar (ohne Auth, nur Ping)
- Output: Farbig (grün/rot) mit Latenz in ms
- Exit-Code: 0 wenn alle erreichbar, 1 sonst

#### E.3 ProfileController Template erweitern
- Template: `templates/profile.html.twig`
- Zeigt:
  - Alle Claims (Tabelle)
  - Token-Status (Expiration)
  - Rollen (global + client)
  - Permissions + Groups

### Feature-Details

#### F.3 Backchannel Logout (OpenID Connect Back-Channel Logout 1.0) ✅

**Implementiert:**
- Endpoint: `POST /auth/backchannel-logout`
- Logout Token (JWT) validiert mit Signatur
- `events` Claim Validierung per Spec
- Event: `OidcBackchannelLogoutEvent` für App-spezifische Session-Invalidierung

**Konfiguration:**
```yaml
eurip_sso:
    routes:
        backchannel_logout: /auth/backchannel-logout
```

**Event-Listener Beispiel:**
```php
#[AsEventListener(event: OidcBackchannelLogoutEvent::NAME)]
class BackchannelLogoutListener
{
    public function __invoke(OidcBackchannelLogoutEvent $event): void
    {
        // Invalidate all sessions for user
        $this->sessionService->invalidateBySubject($event->subject);
        $event->markHandled();
    }
}
```

#### F.7 Session Management (OpenID Connect Session Management 1.0)
- `session_state` aus Authorization Response speichern
- JavaScript-Komponente für Hidden Iframe (`check_session_iframe`)
- postMessage-basiertes Polling
- Event: `OidcSessionChangedEvent`
```yaml
eurip_sso:
    session_management:
        enabled: true
        polling_interval: 5000  # ms
        auto_logout: false
```

#### F.8 Front-Channel Logout (OpenID Connect Front-Channel Logout 1.0) ✅

**Implementiert:**
- Endpoint: `GET /auth/frontchannel-logout`
- Query-Parameter: `iss`, `sid` (optional)
- Issuer-Validierung gegen konfigurierte Werte
- Lokale Session invalidieren
- HTML-Response für Iframe (keine X-Frame-Options)
- Event: `OidcFrontchannelLogoutEvent`

**Konfiguration:**
```yaml
eurip_sso:
    routes:
        frontchannel_logout: /auth/frontchannel-logout
```

**Event-Listener Beispiel:**
```php
#[AsEventListener(event: OidcFrontchannelLogoutEvent::NAME)]
class FrontchannelLogoutListener
{
    public function __invoke(OidcFrontchannelLogoutEvent $event): void
    {
        // Additional cleanup (cache, tokens, etc.)
        $this->cacheService->clearForUser($event->issuer);
        $event->markHandled();
    }
}
```
