# OIDC Session Management

Dieses Bundle unterstützt [OIDC Session Management](https://openid.net/specs/openid-connect-session-1_0.html), womit deine Anwendung erkennen kann, wenn sich die SSO-Session des Users geändert hat (z.B. Logout in einer anderen Anwendung).

## Funktionsweise

```
┌─────────────────┐                          ┌─────────────────┐
│  Deine App      │                          │  SSO Provider   │
│  (Browser)      │                          │                 │
└────────┬────────┘                          └────────┬────────┘
         │                                            │
         │  Versteckter iframe lädt check_session     │
         │ ──────────────────────────────────────────►│
         │                                            │
         │  Alle N Sekunden: postMessage              │
         │  "client_id session_state"                 │
         │ ──────────────────────────────────────────►│
         │                                            │
         │  Antwort: "changed" | "unchanged"          │
         │ ◄──────────────────────────────────────────│
         │                                            │
    ┌────┴────┐                                       │
    │ Wenn    │  → Seite neu laden / Logout /         │
    │"changed"│     Custom-Aktion                     │
    └─────────┘                                       │
```

## Voraussetzungen

1. **SSO Provider muss Session Management unterstützen**
   - Der Provider muss `check_session_iframe` im Discovery Document exponieren
   - EURIP SSO unterstützt das bereits

2. **Session State muss gespeichert sein**
   - Der `session_state` Parameter aus der Authorization Response muss gespeichert werden
   - Dieses Bundle macht das automatisch

## Schnellstart

Füge die Session Monitor Komponente zu deinem Base-Template hinzu:

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
<head>
    {# ... #}
</head>
<body>
    {# ... dein Content ... #}

    {# Vor dem schließenden body-Tag einfügen #}
    {% include '@EuripSso/components/SessionMonitor.html.twig' %}
</body>
</html>
```

Das war's! Die Komponente wird:
- Einen versteckten iframe laden, der auf den `check_session_iframe` des SSO Providers zeigt
- Alle 5 Sekunden pollen (konfigurierbar)
- Die Seite neu laden, wenn sich der Session State ändert

## Konfigurationsoptionen

### Benutzerdefiniertes Polling-Intervall

```twig
{% include '@EuripSso/components/SessionMonitor.html.twig' with {
    interval: 10000
} %}
```

### Benutzerdefinierter Change-Handler

Statt neu zu laden, zum Logout weiterleiten:

```twig
{% include '@EuripSso/components/SessionMonitor.html.twig' with {
    onChanged: 'window.location.href = "/logout"'
} %}
```

Oder eine Benachrichtigung anzeigen:

```twig
{% include '@EuripSso/components/SessionMonitor.html.twig' with {
    onChanged: 'alert("Deine Session ist abgelaufen. Bitte erneut einloggen.")'
} %}
```

## Twig-Funktionen

### `sso_supports_session_management()`

Gibt `true` zurück, wenn Session Management verfügbar ist:

```twig
{% if sso_supports_session_management() %}
    <p>Session-Monitoring ist aktiv</p>
{% endif %}
```

### `sso_session_management_config(interval)`

Gibt die Konfiguration für Session Management zurück:

```twig
{% set config = sso_session_management_config(5000) %}
{# Gibt zurück: {checkSessionIframe: "...", clientId: "...", sessionState: "...", interval: 5000} #}
```

## Manuelle JavaScript-Integration

Wenn du Session Management selbst handhaben möchtest:

```javascript
// Config aus Twig holen
const config = {{ sso_session_management_config()|json_encode|raw }};

if (config) {
    const iframe = document.createElement('iframe');
    iframe.src = config.checkSessionIframe;
    iframe.style.display = 'none';
    document.body.appendChild(iframe);

    iframe.onload = () => {
        setInterval(() => {
            const message = config.clientId + ' ' + config.sessionState;
            iframe.contentWindow.postMessage(message, new URL(config.checkSessionIframe).origin);
        }, config.interval);
    };

    window.addEventListener('message', (event) => {
        if (event.origin === new URL(config.checkSessionIframe).origin) {
            if (event.data === 'changed') {
                console.log('Session geändert!');
                // Deine Custom-Logik hier
            }
        }
    });
}
```

## Fehlerbehebung

### Session-Monitoring funktioniert nicht

1. **Prüfen ob unterstützt:**
   ```twig
   {{ dump(sso_supports_session_management()) }}
   ```

2. **Config prüfen:**
   ```twig
   {{ dump(sso_session_management_config()) }}
   ```

3. **`check_session_iframe` im Discovery prüfen:**
   ```bash
   curl https://your-sso/.well-known/openid-configuration | jq .check_session_iframe
   ```

### Cross-Origin-Probleme

Der `check_session_iframe` verwendet `postMessage`, was korrektes CORS-Setup erfordert. Stelle sicher:
- Der SSO Provider erlaubt deine Domain
- Keine `X-Frame-Options: DENY` Header blockieren den iframe

## Sicherheitsüberlegungen

- Der `session_state` ist nicht sensitiv - es ist ein Hash der Session
- Der iframe erhält nur "changed"/"unchanged"/"error" als Antworten
- Keine Tokens oder User-Daten werden via postMessage ausgetauscht
