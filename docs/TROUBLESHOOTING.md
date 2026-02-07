# Troubleshooting Guide

Häufige Probleme und Lösungen bei der Integration des EURIP SSO Bundles.

🇬🇧 [English Version](#english)

---

## Inhaltsverzeichnis

1. [Invalid State nach Login](#1-invalid-state-nach-login)
2. [Token Signature Verification Failed](#2-token-signature-verification-failed)
3. [Discovery URL nicht erreichbar](#3-discovery-url-nicht-erreichbar)
4. [User not found nach Callback](#4-user-not-found-nach-callback)
5. [Session wird nicht gespeichert](#5-session-wird-nicht-gespeichert)
6. [CORS-Fehler bei API-Aufrufen](#6-cors-fehler-bei-api-aufrufen)
7. [Logout funktioniert nicht](#7-logout-funktioniert-nicht)
8. [Claims fehlen im Token](#8-claims-fehlen-im-token)

---

## 1. Invalid State nach Login

### Symptom
```
Error: Invalid state parameter
```
oder
```
OidcAuthenticationException: State validation failed
```

### Ursachen & Lösungen

#### A) Session-Cookie wird nicht gesetzt/gelesen

**Problem:** Browser blockiert Cookies oder SameSite-Policy verhindert Cookie-Übertragung.

**Lösung:**
```yaml
# config/packages/framework.yaml
framework:
    session:
        cookie_samesite: lax
        cookie_secure: auto
        cookie_httponly: true
```

Bei Cross-Domain-Redirects (SSO auf anderer Domain):
```yaml
cookie_samesite: none
cookie_secure: true  # HTTPS erforderlich!
```

#### B) Session-Storage-Problem

**Problem:** Session-Daten gehen verloren zwischen Login-Initiierung und Callback.

**Prüfen:**
```php
// In einem Controller temporär testen
dump(session_status()); // Sollte PHP_SESSION_ACTIVE sein
dump($_SESSION);        // Sollte State/Nonce enthalten
```

**Lösung:** Session-Handler prüfen:
```yaml
# config/packages/framework.yaml
framework:
    session:
        handler_id: session.handler.native_file
        save_path: '%kernel.project_dir%/var/sessions/%kernel.environment%'
```

#### C) Doppelter Callback-Aufruf

**Problem:** Browser sendet Callback zweimal (z.B. durch Prefetch oder Retry).

**Lösung:** Das Bundle hat bereits Replay-Protection mit TTL. Prüfe ob der erste Callback erfolgreich war:
```bash
# Symfony Logs prüfen
tail -f var/log/dev.log | grep -i "oidc\|state"
```

#### D) Load Balancer ohne Sticky Sessions

**Problem:** Bei mehreren App-Servern landet Callback auf anderem Server als Login.

**Lösung:**
- Sticky Sessions aktivieren, oder
- Shared Session Storage (Redis):
```yaml
framework:
    session:
        handler_id: Symfony\Component\HttpFoundation\Session\Storage\Handler\RedisSessionHandler
```

---

## 2. Token Signature Verification Failed

### Symptom
```
ClaimsValidationException: Token signature verification failed
```

### Ursachen & Lösungen

#### A) JWKS nicht gecached / veraltet

**Problem:** JWKS-Endpoint nicht erreichbar oder Cache abgelaufen während Validierung.

**Lösung:** Cache warmup:
```bash
bin/console eurip:sso:cache:warmup
```

Oder manuell JWKS prüfen:
```bash
curl https://sso.example.com/.well-known/jwks.json
```

#### B) Key Rotation am IdP

**Problem:** IdP hat Keys rotiert, Bundle hat noch alte JWKS gecached.

**Lösung:** Cache leeren:
```bash
bin/console cache:clear
bin/console eurip:sso:cache:warmup --force
```

#### C) Clock Skew

**Problem:** Server-Uhren zwischen App und IdP sind nicht synchronisiert.

**Symptom:** Token wird als "expired" abgelehnt obwohl gerade ausgestellt.

**Lösung:** NTP auf beiden Servern prüfen:
```bash
timedatectl status
# oder
ntpdate -q pool.ntp.org
```

#### D) Falscher Issuer konfiguriert

**Problem:** `issuer` in Config stimmt nicht mit `iss` Claim im Token überein.

**Prüfen:**
```bash
# Token dekodieren (ohne Validierung)
echo "eyJhbG..." | cut -d. -f2 | base64 -d | jq .iss
```

**Lösung:** Issuer in Config korrigieren oder `public_issuer` nutzen:
```yaml
eurip_sso:
    issuer: 'http://sso-internal:8080'      # Für Discovery (intern)
    public_issuer: 'https://sso.example.com' # Für Token-Validierung (extern)
```

---

## 3. Discovery URL nicht erreichbar

### Symptom
```
HTTP 404/500 beim Zugriff auf /.well-known/openid-configuration
```
oder
```
cURL error 6: Could not resolve host
```

### Ursachen & Lösungen

#### A) Container-Networking (Docker/Kubernetes)

**Problem:** App-Container kann SSO-Container nicht erreichen.

**Lösung für Docker Compose:**
```yaml
# docker-compose.yml
services:
  app:
    networks:
      - sso-network

  sso:
    networks:
      - sso-network

networks:
  sso-network:
    external: true  # Oder gemeinsames Netzwerk definieren
```

**Lösung für Kubernetes:**
```yaml
eurip_sso:
    issuer: 'http://sso-service.sso-namespace.svc.cluster.local'
    public_issuer: 'https://sso.example.com'
```

#### B) SSL/TLS-Zertifikat-Probleme

**Problem:** Self-signed Zertifikat oder abgelaufenes Zertifikat.

**Temporäre Lösung (nur Development!):**
```yaml
# config/packages/framework.yaml
framework:
    http_client:
        default_options:
            verify_peer: false
            verify_host: false
```

**Production-Lösung:** Gültiges Zertifikat installieren oder CA-Bundle konfigurieren.

#### C) Firewall/Proxy blockiert

**Problem:** Ausgehende Verbindungen werden blockiert.

**Prüfen:**
```bash
# Vom App-Container aus testen
curl -v https://sso.example.com/.well-known/openid-configuration
```

**Lösung:** Proxy konfigurieren:
```yaml
framework:
    http_client:
        default_options:
            proxy: 'http://proxy.company.com:8080'
```

---

## 4. User not found nach Callback

### Symptom
```
UserNotFoundException: User with subject "abc123" not found
```
oder User wird nicht erstellt.

### Ursachen & Lösungen

#### A) auto_create ist deaktiviert

**Problem:** Bundle soll User erstellen, aber `auto_create: false`.

**Lösung:**
```yaml
eurip_sso:
    user_provider:
        auto_create: true
```

#### B) Mapping-Fehler

**Problem:** Entity-Felder stimmen nicht mit Mapping überein.

**Prüfen:**
```php
// User Entity muss diese Felder haben
private ?string $oidcSubject = null;  // Mapped zu 'subject'
private ?string $oidcIssuer = null;   // Mapped zu 'issuer'
```

**Config:**
```yaml
user_provider:
    entity: App\Entity\User
    mapping:
        subject: oidcSubject  # Entity-Property-Name
        issuer: oidcIssuer
```

#### C) Doctrine-Fehler beim Speichern

**Problem:** Entity kann nicht persistiert werden (Constraint-Violation, etc.).

**Lösung:** Logs prüfen und Entity-Constraints anpassen:
```bash
tail -f var/log/dev.log | grep -i "doctrine\|constraint"
```

#### D) Event-Listener blockiert

**Problem:** Ein `OidcUserCreatedEvent` Listener wirft Exception.

**Lösung:** Listener prüfen:
```php
#[AsEventListener(event: OidcUserCreatedEvent::NAME)]
class MyListener
{
    public function __invoke(OidcUserCreatedEvent $event): void
    {
        // Keine Exceptions werfen!
        // Oder try-catch verwenden
    }
}
```

---

## 5. Session wird nicht gespeichert

### Symptom
- Nach Login sofort wieder ausgeloggt
- `getUser()` gibt `null` zurück

### Ursachen & Lösungen

#### A) Security Firewall falsch konfiguriert

**Problem:** Firewall nutzt falschen Provider.

**Lösung:**
```yaml
# config/packages/security.yaml
security:
    providers:
        app_user_provider:
            id: Jostkleigrewe\Sso\Bundle\Security\DoctrineOidcUserProvider

    firewalls:
        main:
            provider: app_user_provider
            # NICHT: stateless: true
```

#### B) Authenticator fehlt

**Problem:** Kein Authenticator für die Firewall konfiguriert.

**Lösung:**
```yaml
firewalls:
    main:
        custom_authenticator: App\Security\NoopAuthenticator
```

Minimaler NoopAuthenticator:
```php
class NoopAuthenticator extends AbstractAuthenticator
{
    public function supports(Request $request): ?bool
    {
        return false; // Bundle übernimmt Auth
    }

    public function authenticate(Request $request): Passport
    {
        throw new \LogicException('Should not be called');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }
}
```

---

## 6. CORS-Fehler bei API-Aufrufen

### Symptom
```
Access-Control-Allow-Origin header missing
```

### Lösung

CORS ist normalerweise kein Problem für OIDC (Browser-Redirects), aber für API-Aufrufe:

```yaml
# config/packages/nelmio_cors.yaml (wenn installiert)
nelmio_cors:
    paths:
        '^/api/':
            origin_regex: true
            allow_origin: ['%env(CORS_ALLOW_ORIGIN)%']
            allow_headers: ['Authorization', 'Content-Type']
            allow_methods: ['GET', 'POST', 'PUT', 'DELETE']
```

---

## 7. Logout funktioniert nicht

### Symptom
- HTTP 405 Method Not Allowed
- Lokale Session wird beendet, aber SSO-Session bleibt aktiv
- Redirect zum IdP schlägt fehl

### Ursachen & Lösungen

#### A) Logout ist POST-only (seit v1.x)

**Problem:** Logout-Link verwendet GET statt POST.

**Lösung:** Logout muss als Formular mit CSRF-Token gesendet werden:
```twig
{# Falsch: <a href="{{ path('eurip_sso_logout') }}">Logout</a> #}

{# Richtig: #}
<form action="{{ path('eurip_sso_logout') }}" method="POST" style="display:inline">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token('eurip_sso_logout') }}">
    <button type="submit">Logout</button>
</form>
```

Für einen Logout-Link mit JavaScript:
```twig
<a href="#" onclick="document.getElementById('logout-form').submit(); return false;">Logout</a>
<form id="logout-form" action="{{ path('eurip_sso_logout') }}" method="POST" style="display:none">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token('eurip_sso_logout') }}">
</form>
```

### Ursachen & Lösungen

#### B) end_session_endpoint fehlt

**Problem:** IdP unterstützt kein RP-Initiated Logout.

**Prüfen:**
```bash
curl https://sso.example.com/.well-known/openid-configuration | jq .end_session_endpoint
```

**Lösung:** Nur lokalen Logout verwenden:
```php
#[AsEventListener(event: OidcPreLogoutEvent::NAME)]
class LocalLogoutListener
{
    public function __invoke(OidcPreLogoutEvent $event): void
    {
        $event->skipSsoLogout();
    }
}
```

#### C) id_token fehlt für Logout

**Problem:** Bundle braucht `id_token_hint` für SSO-Logout, aber Token ist nicht mehr verfügbar.

**Lösung:** ID Token in Session speichern (bereits Standard):
```yaml
eurip_sso:
    client_services:
        store_access_token: true  # Speichert auch ID Token
```

---

## 8. Claims fehlen im Token

### Symptom
- `$claims->getEmail()` gibt `null` zurück
- Erwartete Rollen fehlen

### Ursachen & Lösungen

#### A) Scopes nicht angefordert

**Problem:** Fehlende Scopes in der Anfrage.

**Lösung:**
```yaml
eurip_sso:
    scopes: [openid, profile, email, roles]
```

Oder dynamisch via Event:
```php
#[AsEventListener(event: OidcPreLoginEvent::NAME)]
class AddScopesListener
{
    public function __invoke(OidcPreLoginEvent $event): void
    {
        $event->setScopes(['openid', 'profile', 'email', 'roles']);
    }
}
```

#### B) Client nicht für Scope berechtigt

**Problem:** SSO-Client hat Scope nicht in `allowed_scopes`.

**Lösung:** Im SSO-Admin-Panel den Client bearbeiten und Scopes hinzufügen.

#### C) User hat Consent nicht gegeben

**Problem:** User hat bei Consent bestimmte Scopes abgelehnt.

**Lösung:** Consent im SSO zurücksetzen oder User neu einloggen lassen.

---

## Debug-Tipps

### 1. Debug-Seite nutzen

```yaml
eurip_sso:
    routes:
        debug: /auth/debug
```

Dann `/auth/debug` aufrufen für OIDC-Konfiguration und Token-Status.

### 2. Symfony Profiler

Im Profiler unter "Security" → Token-Details und Claims einsehen.

### 3. Logging aktivieren

```yaml
# config/packages/monolog.yaml
monolog:
    channels: [oidc]
    handlers:
        oidc:
            type: stream
            path: '%kernel.logs_dir%/oidc.log'
            level: debug
            channels: [oidc]
```

### 4. Token manuell dekodieren

```bash
# JWT Payload anzeigen (ohne Validierung)
echo "eyJhbGciOiJS..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

### 5. Discovery manuell prüfen

```bash
curl -s https://sso.example.com/.well-known/openid-configuration | jq .
```

---

## Hilfe benötigt?

1. **Logs prüfen:** `var/log/dev.log` und `var/log/oidc.log`
2. **Debug-Seite:** `/auth/debug` für Konfigurationsübersicht
3. **GitHub Issues:** [Repository Issues](https://github.com/jostkleigrewe/lib-php-eurip-sso/issues)

---

<a name="english"></a>
# English Version

## Quick Reference

| Problem | Likely Cause | Quick Fix |
|---------|--------------|-----------|
| Invalid state | Session cookie issues | Check `cookie_samesite` setting |
| Signature failed | JWKS cache stale | `bin/console eurip:sso:cache:warmup` |
| Discovery unreachable | Network/DNS | Check container networking |
| User not found | Mapping mismatch | Verify entity field names |
| Session lost | Firewall config | Check security.yaml provider |
| Logout 405 error | GET instead of POST | Use POST form with CSRF token |
| Logout fails | No end_session_endpoint | Use `skipSsoLogout()` event |
| Claims missing | Scopes not requested | Add scopes to config |

For detailed explanations, see the German sections above (code examples are language-independent).
