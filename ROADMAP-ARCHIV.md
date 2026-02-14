# ROADMAP-ARCHIV: OIDC Auth Bundle

> Archivierte erledigte Features und Implementierungsdetails.
> **Status:** Projekt abgeschlossen (2026-02-14)

---

## Archiviert am: 2026-02-14 (Finale Phasen 1-4)

### Phase 1: Bug-Fixes (Quick Wins) ✅

- **1.1 Cache-Key im Warmup-Command fixen** — `OidcClientFactory::buildJwksCacheKey()` extrahiert
- **1.2 TokenExchangeFailedException** — sprintf() statt String-Interpolation

### Phase 2: Auth-Architektur + Bundle modernisieren ✅

- **2.1** OidcAuthenticationException erstellt
- **2.2** OidcAuthenticator modernisiert (delegiert an OidcAuthenticationService)
- **2.3** AuthenticationController::callback() → LogicException-Fallback
- **2.4** Bundle-Config vereinfacht (client_services.enabled, controller.enabled entfernt)
- **2.5** Authenticator Service-Registrierung mit #[Autowire]
- **2.6** Service-Registrierung modernisiert (Resource-Scanning, ~280 Zeilen statt 528)
- **2.7** Authenticator-Config Parameter-Mapping auf routes.*

### Phase 3: Code-Bereinigung ✅

- **3.1** DoctrineOidcUserProvider entdupliziert (buildRoles(), wrapUser())
- **3.2** Stille Catches → Logging
- **3.3** getEntityId() robuster (Composite-Key-Warning)
- **3.4** OidcConstants: Interface → final class, 9 EVENT_*-Constants entfernt
- **3.5** Event-Dispatch modernisiert (klassen-basiert statt String)
- **3.6** EuripSsoFacade entfernt, ID-Token-Verifikation aktiviert
- **3.7** RouteLoader entfernt → #[Route]-Attribute

### Phase 4: JWT-Extraktion + Tests ✅

- **4.1** JwtVerifier extrahiert (Crypto-Code, JWKS Key-Rotation-Resilience)
- **4.2** JwtVerifier-Tests mit echtem RSA-Key (15 Tests)

---

## Breaking Changes (Version nach Archivierung)

### Konfiguration entfernt

| Entfernt | Migration |
|----------|-----------|
| `controller.enabled` | Weg — Controller immer registriert |
| `client_services.enabled` | Weg — Services immer registriert |
| `authenticator.callback_route` | Weg — nutzt `routes.callback` |
| `authenticator.login_path` | Weg — nutzt `routes.login` |
| `authenticator.default_target_path` | Weg — nutzt `routes.after_login` |

### Service-Aliase entfernt

`eurip_sso.facade`, `eurip_sso.claims`, `eurip_sso.auth`, `eurip_sso.api`, `eurip_sso.token_storage` → direkte Type-Hints verwenden

### EuripSsoFacade komplett entfernt

Direkt `EuripSsoClaimsService`, `EuripSsoAuthorizationService`, `EuripSsoApiClient`, `EuripSsoTokenStorage` injecten.

### OidcConstants: Interface → final class

`implements OidcConstants` entfernen, Constants direkt referenzieren.

### Event-Dispatch: String → Klassen-basiert

`dispatch($event, OidcConstants::EVENT_*)` → `dispatch($event)`

### OidcClient Constructor

Neuer Parameter `JwtVerifier` — `OidcClientFactory` erledigt das automatisch.

---

## Erledigte Phasen (1-12)

| Phase | Beschreibung | Status |
|-------|--------------|--------|
| 1 | Bundle-Routen & Controller | ✅ |
| 2 | State/Session Management | ✅ |
| 3 | Auto User-Provisionierung | ✅ |
| 4 | Generische OidcUser | ✅ |
| 5 | JWT-Duplikate entfernen (~1320 Zeilen) | ✅ |
| 6 | Events erweitern (6 Events) | ✅ |
| 7 | Cleanup & Dokumentation | ✅ |
| 8 | Security Hardening | ✅ |
| 9 | Architecture Refactoring | ✅ |
| 10 | Error Handling & Resilience | ✅ |
| 11 | Performance & Optimization | ✅ |
| 12 | Code Quality & Testing | ✅ |

---

## Erledigte externe Anforderungen (E.1-E.3)

### E.1 Twig-Extension ✅

**Implementiert:** `src/Bundle/Twig/EuripSsoTwigExtension.php`

**Funktionen:**
| Funktion | Beschreibung |
|----------|--------------|
| `sso_is_authenticated()` | Prüft ob User authentifiziert |
| `sso_email()` | E-Mail des eingeloggten Users |
| `sso_name()` | Name des Users |
| `sso_user_id()` | Subject (User-ID) |
| `sso_has_role(role)` | Prüft Rolle (global oder client) |
| `sso_has_permission(permission)` | Prüft Permission |
| `sso_has_group(group)` | Prüft Gruppenmitgliedschaft |
| `sso_claim(name, default)` | Beliebiger Claim-Wert |

**Registrierung:** Automatisch wenn `client_services.enabled: true` und Twig verfügbar.

**Beispiel:**
```twig
{% if sso_is_authenticated() %}
    Hello {{ sso_name() ?? sso_email() }}!
    {% if sso_has_role('ROLE_ADMIN') %}
        <a href="/admin">Admin Panel</a>
    {% endif %}
{% endif %}
```

---

### E.2 Console Command: test-connection ✅

**Implementiert:** `src/Bundle/Command/OidcTestConnectionCommand.php`

**Aufruf:**
```bash
bin/console eurip:sso:test-connection
```

**Prüft:**
| Endpoint | Erwartung |
|----------|-----------|
| Discovery | HTTP 200 + JSON |
| JWKS | HTTP 200 + JSON |
| Token | Erreichbar (< 500) |
| UserInfo | Erreichbar (< 500) |
| End-Session | Erreichbar (optional) |

**Output:** Farbig mit Latenz, Exit-Code 0/1.

---

### E.3 ProfileController Template ✅

**Implementiert:**
- `src/Bundle/Controller/ProfileController.php`
- `templates/profile.html.twig`

**Zeigt (wenn client_services.enabled):**
| Bereich | Informationen |
|---------|---------------|
| User Profile | Identifier, Email, Issuer, Subject, Local ID |
| Token Status | Valid/Expired, Expires At, Remaining Time, Refresh Token |
| Roles & Permissions | Global Roles, Client Roles, Symfony Roles, Permissions, Groups |
| All Claims | Tabelle aller ID-Token Claims |
| Debug | JSON-Dump des User-Objekts |

---

## Erledigte Features

### F.3 Backchannel Logout ✅

**Implementiert:**
- Endpoint: `POST /auth/backchannel-logout`
- Logout Token (JWT) validiert mit Signatur
- `events` Claim Validierung per Spec
- Event: `OidcBackchannelLogoutEvent`

**Konfiguration:**
```yaml
eurip_sso:
    routes:
        backchannel_logout: /auth/backchannel-logout
```

---

### F.8 Front-Channel Logout ✅

**Implementiert:**
- Endpoint: `GET /auth/frontchannel-logout`
- Query-Parameter: `iss`, `sid` (optional)
- Issuer-Validierung
- Event: `OidcFrontchannelLogoutEvent`

**Konfiguration:**
```yaml
eurip_sso:
    routes:
        frontchannel_logout: /auth/frontchannel-logout
```

---

### D.1 Troubleshooting-Guide ✅

Dokumentation für häufige Fehler und deren Lösungen.
