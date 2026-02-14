# Device Code Flow (RFC 8628)

🇬🇧 [English Version](DEVICE-CODE-FLOW.md)

## Überblick

Der Device Authorization Grant (RFC 8628) ermöglicht Authentifizierung auf Geräten, die entweder keinen Browser haben oder eingeschränkte Eingabemöglichkeiten bieten. Typische Anwendungsfälle:

- **CLI-Tools** - Kommandozeilen-Anwendungen
- **Smart TVs** - TV-Apps ohne Tastatur
- **IoT-Geräte** - Geräte mit Display aber ohne Browser
- **Spielekonsolen** - Login ohne Passwort-Eingabe

## Funktionsweise

```
┌─────────────────┐                              ┌─────────────────┐
│  Gerät/CLI      │                              │  OIDC Provider  │
│  (Deine App)    │                              │  (SSO Server)   │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  1. POST /oidc/device/authorize                │
         │     client_id, scope                           │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  2. Antwort:                                   │
         │     device_code, user_code,                    │
         │     verification_uri, expires_in               │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         │  3. Anzeige für Benutzer:                      │
         │     "Öffne: https://sso.example.com/device"    │
         │     "Code: ABCD-EFGH"                          │
         │                                                │
         │                    ┌─────────────────┐         │
         │                    │ Browser des     │         │
         │                    │ Benutzers       │         │
         │                    │ (z.B. Handy)    │         │
         │                    └────────┬────────┘         │
         │                             │                  │
         │                             │ 4. Benutzer      │
         │                             │    öffnet URL,   │
         │                             │    gibt Code ein │
         │                             │    und loggt ein │
         │                             │ ────────────────►│
         │                             │                  │
         │  5. Polling: POST /oidc/token                  │
         │     grant_type=device_code, device_code        │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  6a. "authorization_pending" (weiter pollen)   │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         │  ... (alle 5 Sekunden wiederholen) ...         │
         │                                                │
         │  6b. Erfolg: access_token, refresh_token       │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         ▼                                                ▼
```

## Voraussetzungen

### Provider-Anforderungen

Der OIDC Provider muss RFC 8628 unterstützen. Prüfe das Discovery-Dokument:

```bash
curl https://sso.example.com/.well-known/openid-configuration | jq '.device_authorization_endpoint'
```

Wenn die Antwort `null` ist, unterstützt der Provider keinen Device Code Flow.

### Bundle-Konfiguration

Keine spezielle Konfiguration nötig. Das Bundle erkennt `device_authorization_endpoint` automatisch aus dem Discovery-Dokument.

## Verwendung

### CLI-Command (Empfohlen für CLI-Apps)

```bash
# Interaktiver Login mit visueller Rückmeldung
bin/console eurip:sso:device-login

# Mit eigenen Scopes
bin/console eurip:sso:device-login --scopes="openid,profile,email,roles"

# Nur Access Token ausgeben (für Scripting)
ACCESS_TOKEN=$(bin/console eurip:sso:device-login --output-token)
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://api.example.com/me

# Vollständige JSON-Response
bin/console eurip:sso:device-login --output-json > tokens.json
```

### Programmatische Nutzung (Blockierend)

```php
use Jostkleigrewe\Sso\Client\OidcClient;

// OidcClient injizieren oder erstellen
public function login(OidcClient $oidcClient): void
{
    // 1. Device Code anfordern
    $deviceCode = $oidcClient->requestDeviceCode(['openid', 'profile', 'email']);

    // 2. Anweisungen für Benutzer anzeigen
    $this->output->writeln("Zum Anmelden öffne: {$deviceCode->verificationUri}");
    $this->output->writeln("Code eingeben: {$deviceCode->getFormattedUserCode()}");

    // Optional: Komplette URL anzeigen (mit vorausgefülltem Code)
    if ($deviceCode->verificationUriComplete !== null) {
        $this->output->writeln("Oder direkt öffnen: {$deviceCode->verificationUriComplete}");
    }

    // 3. Auf Autorisierung warten (blockierend)
    $tokenResponse = $oidcClient->awaitDeviceToken(
        $deviceCode,
        // Optional: Fortschritts-Callback
        fn(int $attempt, int $interval) => $this->output->write('.'),
    );

    // 4. Tokens verwenden
    $accessToken = $tokenResponse->accessToken;
    $refreshToken = $tokenResponse->refreshToken; // Kann null sein
    $idToken = $tokenResponse->idToken;           // Kann null sein
}
```

### Programmatische Nutzung (Manuelles Polling)

Für mehr Kontrolle über den Polling-Prozess:

```php
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\DTO\DeviceCodePollResult;

public function loginWithManualPolling(OidcClient $oidcClient): void
{
    $deviceCode = $oidcClient->requestDeviceCode(['openid', 'profile']);

    $this->displayInstructions($deviceCode);

    $interval = $deviceCode->interval; // Normalerweise 5 Sekunden
    $startTime = time();
    $maxWaitTime = $deviceCode->expiresIn;

    while (true) {
        // Timeout prüfen
        if ((time() - $startTime) > $maxWaitTime) {
            throw new \RuntimeException('Device Code abgelaufen');
        }

        // Vor dem Polling warten (RFC 8628 Pflicht)
        sleep($interval);

        // Token abfragen
        $result = $oidcClient->pollDeviceToken($deviceCode->deviceCode, $interval);

        switch ($result->status) {
            case DeviceCodePollResult::STATUS_SUCCESS:
                // Erfolg! Token erhalten
                $this->handleSuccess($result->tokenResponse);
                return;

            case DeviceCodePollResult::STATUS_PENDING:
                // Benutzer hat noch nicht autorisiert, weiter pollen
                $this->output->write('.');
                break;

            case DeviceCodePollResult::STATUS_SLOW_DOWN:
                // Zu schnell gepollt, Intervall erhöhen
                $interval = $result->getRecommendedInterval($interval);
                $this->output->writeln("Verlangsame auf {$interval}s Intervall");
                break;

            case DeviceCodePollResult::STATUS_ACCESS_DENIED:
                // Benutzer hat abgelehnt
                throw new \RuntimeException('Benutzer hat Autorisierung abgelehnt');

            case DeviceCodePollResult::STATUS_EXPIRED:
                // Device Code abgelaufen
                throw new \RuntimeException('Device Code abgelaufen');
        }
    }
}
```

## API-Referenz

### DeviceCodeResponse

Rückgabe von `requestDeviceCode()`:

| Eigenschaft | Typ | Beschreibung |
|-------------|-----|--------------|
| `deviceCode` | `string` | Der Device-Verifizierungscode (nicht dem Benutzer zeigen) |
| `userCode` | `string` | Der Code, den der Benutzer eingeben muss (z.B. "ABCDEFGH") |
| `verificationUri` | `string` | URL, die der Benutzer öffnen soll |
| `verificationUriComplete` | `?string` | URL mit vorausgefülltem Code (optional) |
| `expiresIn` | `int` | Sekunden bis der Device Code abläuft |
| `interval` | `int` | Mindest-Polling-Intervall in Sekunden (Standard: 5) |

**Hilfsmethoden:**

| Methode | Rückgabe | Beschreibung |
|---------|----------|--------------|
| `getFormattedUserCode()` | `string` | Formatierter Code (z.B. "ABCD-EFGH") |
| `getBestVerificationUri()` | `string` | Gibt `verificationUriComplete` zurück wenn verfügbar |
| `getExpiresAt()` | `DateTimeImmutable` | Ablaufzeitpunkt |
| `isExpired()` | `bool` | Ob der Code abgelaufen ist |

### DeviceCodePollResult

Rückgabe von `pollDeviceToken()`:

| Eigenschaft | Typ | Beschreibung |
|-------------|-----|--------------|
| `status` | `string` | Eine der STATUS_* Konstanten |
| `tokenResponse` | `?TokenResponse` | Tokens bei Erfolg, sonst null |
| `newInterval` | `?int` | Neues Polling-Intervall (bei slow_down) |
| `errorDescription` | `?string` | Fehlermeldung (bei Fehler) |

**Status-Konstanten:**

| Konstante | Bedeutung | Aktion |
|-----------|-----------|--------|
| `STATUS_SUCCESS` | Benutzer hat autorisiert, Tokens erhalten | Polling stoppen, Tokens verwenden |
| `STATUS_PENDING` | Benutzer hat noch nicht autorisiert | Weiter pollen |
| `STATUS_SLOW_DOWN` | Zu schnell gepollt | Intervall erhöhen, weiter pollen |
| `STATUS_ACCESS_DENIED` | Benutzer hat abgelehnt | Stoppen, Fehler anzeigen |
| `STATUS_EXPIRED` | Device Code abgelaufen | Stoppen, neuen Code anfordern |

**Hilfsmethoden:**

| Methode | Rückgabe | Beschreibung |
|---------|----------|--------------|
| `isSuccess()` | `bool` | True wenn Tokens erhalten |
| `shouldContinuePolling()` | `bool` | True wenn pending oder slow_down |
| `isError()` | `bool` | True wenn access_denied oder expired |
| `shouldSlowDown()` | `bool` | True wenn Intervall erhöht werden soll |
| `getRecommendedInterval(int $current)` | `int` | Nächstes zu verwendendes Intervall |

## Fehlerbehandlung

### Häufige Fehler

| Fehler | Ursache | Lösung |
|--------|---------|--------|
| `OidcProtocolException: No device_authorization_endpoint configured` | Provider unterstützt RFC 8628 nicht | Standard-Browser-Flow verwenden |
| `TokenExchangeFailedException: access_denied` | Benutzer hat "Ablehnen" geklickt | Benutzer informieren, Wiederholung anbieten |
| `TokenExchangeFailedException: expired_token` | Benutzer hat nicht rechtzeitig autorisiert | Neuen Device Code anfordern |
| `TokenExchangeFailedException: timeout` | Polling-Loop hat Max-Versuche überschritten | Neuen Device Code anfordern |

### Beispiel für Exception-Handling

```php
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;

try {
    $deviceCode = $oidcClient->requestDeviceCode(['openid']);
    $tokens = $oidcClient->awaitDeviceToken($deviceCode);
} catch (OidcProtocolException $e) {
    // Provider unterstützt Device Flow nicht
    $this->logger->error('Device Flow nicht unterstützt', ['error' => $e->getMessage()]);
    $this->fallbackToBrowserFlow();
} catch (TokenExchangeFailedException $e) {
    match ($e->getErrorCode()) {
        'access_denied' => $this->output->error('Du hast die Autorisierung abgelehnt.'),
        'expired_token' => $this->output->warning('Der Code ist abgelaufen. Bitte erneut versuchen.'),
        'timeout' => $this->output->warning('Zeitüberschreitung beim Warten auf Autorisierung.'),
        default => $this->output->error("Authentifizierung fehlgeschlagen: {$e->getMessage()}"),
    };
}
```

## Timeouts und Intervalle

### Standardwerte

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| Device Code Ablaufzeit | 600s (10 Min) | Zeit die der Benutzer hat um zu autorisieren |
| Polling-Intervall | 5s | Mindestzeit zwischen Polls |
| Slow-Down-Erhöhung | +5s | Wird bei slow_down zum Intervall addiert |

### Best Practices

1. **Intervall immer einhalten** - RFC 8628 erfordert mindestens `interval` Sekunden zwischen Polls
2. **slow_down behandeln** - Bei zu schnellem Polling gibt der Provider `slow_down` zurück
3. **Restzeit anzeigen** - Hilft Benutzern die Dringlichkeit zu verstehen
4. **Abbruch ermöglichen** - Benutzer sollten den Prozess abbrechen können (Ctrl+C im CLI)

## Sicherheitsaspekte

1. **Device Code ist geheim** - Nur `userCode` dem Benutzer zeigen, niemals `deviceCode`
2. **HTTPS erforderlich** - Alle Endpoints müssen in Production HTTPS verwenden
3. **Kurzlebige Codes** - Device Codes laufen schnell ab (normalerweise 10-15 Minuten)
4. **Einmalige Nutzung** - Jeder Device Code kann nur einmal verwendet werden

## Fehlerbehebung

### "No device_authorization_endpoint configured"

**Ursache:** Der OIDC Provider stellt keinen `device_authorization_endpoint` im Discovery-Dokument bereit.

**Lösung:**
1. Prüfe ob dein Provider RFC 8628 unterstützt
2. Discovery-Dokument prüfen: `curl https://dein-sso/.well-known/openid-configuration | jq '.device_authorization_endpoint'`
3. Wenn nicht unterstützt, verwende stattdessen den Standard-Browser-Flow

### "authorization_pending" endlos

**Ursache:** Benutzer hat die Autorisierung im Browser nicht abgeschlossen.

**Checkliste:**
1. Ist die `verification_uri` korrekt und erreichbar?
2. Hat der Benutzer den richtigen `user_code` eingegeben?
3. Hat der Benutzer Login und Consent abgeschlossen?
4. Gibt es Netzwerkprobleme zwischen Browser und SSO?

### "slow_down" Antworten

**Ursache:** Zu häufiges Polling.

**Lösung:** Das Bundle behandelt das automatisch. Bei manuellem Polling immer `$result->getRecommendedInterval()` verwenden.

### "expired_token" zu schnell

**Ursache:** Device Code abgelaufen bevor Benutzer autorisieren konnte.

**Lösungen:**
1. Klare Anweisungen sofort anzeigen
2. Countdown-Timer anzeigen
3. `verification_uri_complete` verwenden für einfachere Mobile-Eingabe

## Referenzen

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 für TV und Geräte mit eingeschränkter Eingabe](https://developers.google.com/identity/protocols/oauth2/limited-input-device)
