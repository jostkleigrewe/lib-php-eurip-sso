# ROADMAP: OIDC Auth Bundle

> Zuletzt aktualisiert: 2026-02-05

---

## Status: Feature-Complete ✅

Das Bundle ist **production-ready** mit allen Kern-Features.

| Komponente | Status |
|------------|--------|
| OidcClient (Core) | ✅ |
| Discovery Caching | ✅ |
| Dual-URL Support (Docker/K8s) | ✅ |
| Claims Validation | ✅ |
| Token Exchange + Refresh | ✅ |
| Events (9 Events) | ✅ |
| Auth Controllers | ✅ |
| User Provisioning | ✅ |
| Back-Channel Logout | ✅ |
| Front-Channel Logout | ✅ |
| Twig-Extension | ✅ |
| Test-Connection Command | ✅ |
| Profile Template | ✅ |
| Tests (48 Tests) | ✅ |
| PHPStan Level 8 | ✅ |

> Erledigte Phasen 1-12 und Details: siehe [ROADMAP-ARCHIV.md](ROADMAP-ARCHIV.md)

---

## Offene Features (Optional)

> Nicht blockierend für Production. Bei Bedarf implementieren.

### Dokumentation

| ID | Feature | Priorität | Status |
|----|---------|-----------|--------|
| D.2 | Sequenzdiagramme (Mermaid) | 🟢 Nice-to-have | ⏳ |

### Testing

| ID | Feature | Priorität | Status |
|----|---------|-----------|--------|
| T.1 | E2E-Tests mit Mock-IdP | 🟡 Empfohlen | ⏳ |
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

## Feature-Details (Offene)

### F.7 Session Management (OpenID Connect Session Management 1.0)

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

### Minimal-Konfiguration

```yaml
eurip_sso:
    issuer: '%env(SSO_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'
    controller:
        enabled: true
    client_services:
        enabled: true
```
