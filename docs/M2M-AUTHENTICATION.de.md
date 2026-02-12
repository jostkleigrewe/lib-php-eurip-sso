# Machine-to-Machine (M2M) Authentifizierung

[English Version](M2M-AUTHENTICATION.md)

## Überblick

Dieser Guide behandelt Authentifizierungs-Flows für **Server-zu-Server-Kommunikation**, bei der kein Benutzer involviert ist. Zwei komplementäre Features werden abgedeckt:

| Feature | RFC | Zweck |
|---------|-----|-------|
| **Client Credentials Grant** | RFC 6749 §4.4 | Access Token ohne User-Interaktion holen |
| **Token Introspection** | RFC 7662 | Eingehende Tokens validieren (für APIs/Resource Server) |

### Typische Anwendungsfälle

- **Cronjobs** - Nächtliche Sync-Jobs die APIs aufrufen
- **Microservices** - Service A authentifiziert sich bei Service B
- **Backend-Integrationen** - ERP-Systeme, Daten-Pipelines
- **Webhooks** - Dein Server ruft externe APIs auf
- **Resource Server** - APIs die eingehende Bearer Tokens validieren

## Funktionsweise

### Client Credentials Grant

```
┌─────────────────┐                              ┌─────────────────┐
│  Dein Server    │                              │  SSO Server     │
│  (z.B. Cronjob) │                              │                 │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  POST /oidc/token                              │
         │  grant_type=client_credentials                 │
         │  client_id + client_secret                     │
         │  scope=api:read                                │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  { access_token, expires_in, scope }           │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         ▼                                                ▼

Kein id_token - es gibt keine User-Identität
Kein refresh_token - Client kann jederzeit neuen Token anfordern
```

### Token Introspection

```
┌─────────────────┐                              ┌─────────────────┐
│  Resource Server│                              │  SSO Server     │
│  (Deine API)    │                              │                 │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  POST /oidc/introspect                         │
         │  token=<eingehender Bearer Token>              │
         │  client_id + client_secret                     │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  { active: true, scope, client_id, exp, ... }  │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         ▼                                                ▼
```

## Voraussetzungen

### SSO-Server-Anforderungen

Prüfe ob dein OIDC-Provider diese Features unterstützt:

```bash
# Discovery-Dokument prüfen
curl https://sso.example.com/.well-known/openid-configuration | jq '{
  grant_types: .grant_types_supported,
  introspection: .introspection_endpoint
}'
```

Erwartete Ausgabe:
```json
{
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "introspection": "https://sso.example.com/oidc/introspect"
}
```

### Client-Konfiguration

Dein Client muss im SSO-Admin konfiguriert sein:

| Einstellung | Wert |
|-------------|------|
| Client-Typ | Confidential |
| Client Secret | Erforderlich |
| Erlaubte Grant Types | `client_credentials` |
| Erlaubte Scopes | Nach Bedarf (z.B. `api:read`, `api:write`) |

### Bundle-Konfiguration

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    client_secret: '%env(OIDC_CLIENT_SECRET)%'  # Erforderlich!
    redirect_uri: '%env(APP_URL)%/auth/callback'
```

## Verwendung

### CLI-Befehle

#### Token via Client Credentials holen

```bash
# Interaktiv - zeigt Token-Details
bin/console eurip:sso:client-credentials

# Mit bestimmten Scopes
bin/console eurip:sso:client-credentials --scopes="api:read,api:write"

# Nur Token ausgeben (für Scripting)
TOKEN=$(bin/console eurip:sso:client-credentials --output-token)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data

# JSON-Ausgabe
bin/console eurip:sso:client-credentials --output-json
```

#### Token validieren (Introspection)

```bash
# Token validieren und inspizieren
bin/console eurip:sso:introspect "eyJhbGciOiJSUzI1NiIs..."

# Mit Token-Type-Hint (beschleunigt Lookup)
bin/console eurip:sso:introspect "$TOKEN" --type=access_token

# JSON-Ausgabe
bin/console eurip:sso:introspect "$TOKEN" --output-json
```

### Programmatische Nutzung

#### Client Credentials Grant

```php
use Jostkleigrewe\Sso\Client\OidcClient;

class OrderSyncCommand extends Command
{
    public function __construct(
        private OidcClient $oidcClient,
        private HttpClientInterface $httpClient,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // 1. Access Token holen (keine User-Interaktion!)
        $token = $this->oidcClient->getClientCredentialsToken(
            scopes: ['orders:read']
        );

        // 2. Geschützte API aufrufen
        $response = $this->httpClient->request('GET',
            'https://api.example.com/orders',
            [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token->accessToken,
                ],
            ]
        );

        // 3. Daten verarbeiten
        $orders = $response->toArray();

        foreach ($orders as $order) {
            $this->processOrder($order);
        }

        return Command::SUCCESS;
    }
}
```

#### Token Introspection (Resource Server)

```php
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

class ApiController
{
    public function __construct(
        private OidcClient $oidcClient,
    ) {}

    public function getOrders(Request $request): JsonResponse
    {
        // 1. Bearer Token extrahieren
        $authHeader = $request->headers->get('Authorization', '');
        if (!str_starts_with($authHeader, 'Bearer ')) {
            return new JsonResponse(['error' => 'Bearer Token fehlt'], 401);
        }
        $token = substr($authHeader, 7);

        // 2. Token via Introspection validieren
        $introspection = $this->oidcClient->introspectToken($token);

        if (!$introspection->active) {
            return new JsonResponse(['error' => 'Token ungültig oder abgelaufen'], 401);
        }

        // 3. Erforderlichen Scope prüfen
        if (!$introspection->hasScope('orders:read')) {
            return new JsonResponse(['error' => 'Unzureichende Berechtigung'], 403);
        }

        // 4. Anfrage verarbeiten
        return new JsonResponse([
            'orders' => $this->orderRepository->findAll(),
            'client_id' => $introspection->clientId,
        ]);
    }
}
```

#### Symfony Security Authenticator

Für einen integrierten Ansatz erstelle einen Custom Authenticator:

```php
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class BearerTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private OidcClient $oidcClient,
    ) {}

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization')
            && str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $token = substr($request->headers->get('Authorization', ''), 7);

        $introspection = $this->oidcClient->introspectToken($token);

        if (!$introspection->active) {
            throw new AuthenticationException('Token ist nicht aktiv');
        }

        // "Machine User" erstellen der den Client repräsentiert
        return new SelfValidatingPassport(
            new UserBadge(
                $introspection->clientId ?? 'unknown',
                fn () => new MachineUser(
                    clientId: $introspection->clientId,
                    scopes: $introspection->getScopes(),
                    subject: $introspection->sub,
                )
            )
        );
    }
}
```

## API-Referenz

### OidcClient-Methoden

#### getClientCredentialsToken()

```php
/**
 * @param list<string> $scopes Angeforderte Scopes (optional)
 * @return TokenResponse Access Token (kein id_token, normalerweise kein refresh_token)
 * @throws OidcProtocolException Wenn kein client_secret konfiguriert ist
 * @throws TokenExchangeFailedException Bei Provider-Fehlern
 */
public function getClientCredentialsToken(array $scopes = []): TokenResponse
```

#### introspectToken()

```php
/**
 * @param string $token Das zu validierende Token
 * @param string|null $tokenTypeHint Optional: "access_token" oder "refresh_token"
 * @return IntrospectionResponse Token-Metadaten (active, scope, client_id, exp, etc.)
 * @throws OidcProtocolException Wenn kein introspection_endpoint konfiguriert ist
 */
public function introspectToken(string $token, ?string $tokenTypeHint = null): IntrospectionResponse
```

### TokenResponse

Rückgabe von `getClientCredentialsToken()`:

| Eigenschaft | Typ | Beschreibung |
|-------------|-----|--------------|
| `accessToken` | `string` | Der Access Token |
| `tokenType` | `string` | Normalerweise "Bearer" |
| `expiresIn` | `int` | Token-Lebensdauer in Sekunden |
| `expiresAt` | `DateTimeImmutable` | Berechneter Ablaufzeitpunkt |
| `scope` | `?string` | Gewährte Scopes (space-separated) |
| `refreshToken` | `?string` | Normalerweise null bei Client Credentials |
| `idToken` | `?string` | Immer null bei Client Credentials |

**Hilfsmethoden:**

| Methode | Rückgabe | Beschreibung |
|---------|----------|--------------|
| `isExpired()` | `bool` | Ob das Token abgelaufen ist |
| `isExpiringSoon(int $buffer = 60)` | `bool` | Ob Token innerhalb des Buffers abläuft |
| `getRemainingSeconds()` | `int` | Sekunden bis zum Ablauf |

### IntrospectionResponse

Rückgabe von `introspectToken()`:

| Eigenschaft | Typ | Beschreibung |
|-------------|-----|--------------|
| `active` | `bool` | Ob das Token gültig ist (REQUIRED) |
| `scope` | `?string` | Token-Scope (space-separated) |
| `clientId` | `?string` | Client für den das Token ausgestellt wurde |
| `username` | `?string` | Menschenlesbarer Identifier |
| `sub` | `?string` | Subject Identifier (User-ID) |
| `tokenType` | `?string` | Token-Typ (z.B. "Bearer") |
| `exp` | `?int` | Ablauf-Timestamp (Unix) |
| `iat` | `?int` | Ausstellungs-Timestamp (Unix) |
| `nbf` | `?int` | Not-Before-Timestamp (Unix) |
| `aud` | `?string` | Zielgruppe (Audience) |
| `iss` | `?string` | Issuer URI |
| `jti` | `?string` | JWT ID (eindeutiger Identifier) |

**Hilfsmethoden:**

| Methode | Rückgabe | Beschreibung |
|---------|----------|--------------|
| `hasScope(string $scope)` | `bool` | Ob Token bestimmten Scope hat |
| `getScopes()` | `list<string>` | Alle Scopes als Array |
| `isExpired()` | `bool` | Ob Token abgelaufen ist |
| `getRemainingSeconds()` | `int` | Sekunden bis zum Ablauf |

## Vollständiges Beispiel: ERP Bestell-Sync

### Das Szenario

Ein ERP-System synchronisiert jede Nacht um 02:00 Bestellungen von einer Shop-API.

### Architektur

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  02:00 Cronjob startet                                         │
│                                                                │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│  │   ERP       │     │   SSO       │     │   Shop      │      │
│  │   Cronjob   │     │   Server    │     │   API       │      │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘      │
│         │                   │                   │              │
│         │  1. Token holen   │                   │              │
│         │ ─────────────────►│                   │              │
│         │ ◄─────────────────│                   │              │
│         │                   │                   │              │
│         │  2. GET /orders (Bearer Token)        │              │
│         │ ──────────────────────────────────────►              │
│         │                   │                   │              │
│         │                   │  3. Introspect    │              │
│         │                   │ ◄─────────────────│              │
│         │                   │ ─────────────────►│              │
│         │                   │                   │              │
│         │  4. Bestellungen JSON                 │              │
│         │ ◄──────────────────────────────────────              │
│         │                   │                   │              │
│         ▼                   ▼                   ▼              │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### ERP-Seite (Client)

```php
// src/Command/SyncOrdersCommand.php

#[AsCommand(name: 'erp:sync-orders')]
final class SyncOrdersCommand extends Command
{
    public function __construct(
        private OidcClient $oidcClient,
        private HttpClientInterface $httpClient,
        private OrderImporter $importer,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // 1. M2M-Token holen
        $token = $this->oidcClient->getClientCredentialsToken(['orders:read']);
        $io->info(sprintf('Token erhalten, läuft ab in %ds', $token->expiresIn));

        // 2. Bestellungen von Shop-API abrufen
        $response = $this->httpClient->request('GET',
            'https://shop.example.com/api/orders?since=yesterday',
            [
                'headers' => ['Authorization' => 'Bearer ' . $token->accessToken],
            ]
        );

        $orders = $response->toArray();
        $io->info(sprintf('%d Bestellungen abgerufen', count($orders)));

        // 3. Bestellungen importieren
        foreach ($orders as $order) {
            $this->importer->import($order);
        }

        $io->success('Bestell-Sync abgeschlossen');

        return Command::SUCCESS;
    }
}
```

### Shop-API-Seite (Resource Server)

```php
// src/Security/BearerTokenAuthenticator.php

final class BearerTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private OidcClient $oidcClient,
    ) {}

    public function authenticate(Request $request): Passport
    {
        $token = $this->extractBearerToken($request);
        $introspection = $this->oidcClient->introspectToken($token, 'access_token');

        if (!$introspection->active) {
            throw new AuthenticationException('Token ist inaktiv');
        }

        return new SelfValidatingPassport(
            new UserBadge(
                $introspection->clientId ?? 'api-client',
                fn () => new ApiClient(
                    clientId: $introspection->clientId,
                    scopes: $introspection->getScopes(),
                )
            )
        );
    }

    private function extractBearerToken(Request $request): string
    {
        $header = $request->headers->get('Authorization', '');

        if (!str_starts_with($header, 'Bearer ')) {
            throw new AuthenticationException('Bearer Token fehlt');
        }

        return substr($header, 7);
    }
}
```

## Sicherheitsaspekte

### Client Credentials

1. **Client Secret schützen** - In Umgebungsvariablen speichern, niemals committen
2. **Minimale Scopes** - Nur anfordern was benötigt wird
3. **Kurze Token-Lebensdauer** - Tokens sollten schnell ablaufen (1 Stunde typisch)
4. **Secrets rotieren** - Regelmäßig Client Secrets wechseln

### Token Introspection

1. **Immer validieren** - Tokens niemals ohne Validierung vertrauen
2. **Scopes prüfen** - Verifizieren dass Token erforderliche Berechtigungen hat
3. **Revocation behandeln** - Tokens können während ihrer Lebensdauer widerrufen werden
4. **Vorsichtig cachen** - Balance zwischen Performance und Revocation-Erkennung

### Introspection vs. Lokale JWT-Validierung

| Aspekt | Introspection | Lokale JWT-Validierung |
|--------|---------------|------------------------|
| Revocation | Sofort | Verzögert (bis Ablauf) |
| Latenz | HTTP-Call erforderlich | Kein Netzwerk nötig |
| SSO-Abhängigkeit | Muss erreichbar sein | Nur für JWKS-Updates |
| Empfohlen für | Hohe Sicherheit, Revocation nötig | Hoher Durchsatz, latenz-sensitiv |

## Fehlerbehebung

### "Client credentials grant requires a client_secret"

**Ursache:** Kein `client_secret` in `eurip_sso.yaml` konfiguriert.

**Lösung:** Secret zur Konfiguration hinzufügen:
```yaml
eurip_sso:
    client_secret: '%env(OIDC_CLIENT_SECRET)%'
```

### "unauthorized_client" Fehler

**Ursache:** Der Client ist nicht für `client_credentials` Grant autorisiert.

**Lösung:** Im SSO-Admin `client_credentials` bei den erlaubten Grant Types aktivieren.

### "invalid_scope" Fehler

**Ursache:** Angeforderter Scope ist nicht für diesen Client erlaubt.

**Lösung:** Erlaubte Scopes des Clients im SSO-Admin prüfen.

### "No introspection_endpoint configured"

**Ursache:** Der OIDC-Provider bietet keinen Introspection-Endpoint an.

**Lösung:** Entweder:
1. Introspection auf dem SSO-Server aktivieren
2. Stattdessen lokale JWT-Validierung verwenden (wenn Access Tokens JWTs sind)

### Token gibt immer `active: false` zurück

**Mögliche Ursachen:**
1. Token ist abgelaufen
2. Token wurde widerrufen
3. Token wurde von einem anderen Client ausgestellt
4. Token-Format ist ungültig
5. Falscher Token-Typ (refresh vs access)

**Debugging:** `--output-json` mit dem Introspect-Command verwenden um Details zu sehen.

## Referenzen

- [RFC 6749 - OAuth 2.0 (Client Credentials)](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- [RFC 7662 - Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [OAuth 2.0 Token Introspection (oauth.net)](https://oauth.net/2/token-introspection/)
