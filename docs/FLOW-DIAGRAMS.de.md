# OIDC Flow-Diagramme

Visuelle Sequenzdiagramme für alle unterstützten Authentifizierungs-Flows.

## Authorization Code Flow (mit PKCE)

Der Standard-Login-Flow für Browser.

```mermaid
sequenceDiagram
    autonumber
    participant User as Benutzer
    participant Browser
    participant App as Deine App
    participant SSO as SSO Provider

    User->>Browser: Klickt "Login"
    Browser->>App: GET /auth/login

    Note over App: Generiere state, nonce, PKCE verifier
    App->>App: In Session speichern

    App->>Browser: Redirect zu /authorize
    Browser->>SSO: GET /authorize?client_id=...&code_challenge=...

    SSO->>Browser: Login-Seite
    User->>Browser: Credentials eingeben
    Browser->>SSO: POST credentials

    alt Consent erforderlich
        SSO->>Browser: Consent-Seite
        User->>Browser: Zustimmen
        Browser->>SSO: POST consent
    end

    SSO->>Browser: Redirect zum Callback
    Browser->>App: GET /auth/callback?code=...&state=...

    Note over App: State validieren
    App->>SSO: POST /token (code + PKCE verifier)
    SSO->>App: {access_token, id_token, refresh_token}

    Note over App: JWT-Signatur & Claims validieren
    App->>App: User erstellen/aktualisieren, Tokens speichern

    App->>Browser: Redirect zur Zielseite
    Browser->>User: Eingeloggt!
```

## Device Authorization Grant (RFC 8628)

Für Geräte ohne Browser (CLI, Smart TV, IoT).

```mermaid
sequenceDiagram
    autonumber
    participant User as Benutzer
    participant Device as CLI / Gerät
    participant Phone as Smartphone
    participant SSO as SSO Provider

    Device->>SSO: POST /device/authorize
    SSO->>Device: {device_code, user_code, verification_uri}

    Device->>User: "Öffne: https://sso/device"
    Device->>User: "Gib ein: ABCD-1234"

    par Gerät pollt nach Token
        loop Alle 5 Sekunden
            Device->>SSO: POST /token (device_code)
            SSO->>Device: {error: "authorization_pending"}
        end
    and Benutzer autorisiert
        User->>Phone: Öffnet verification_uri
        Phone->>SSO: GET /device
        SSO->>Phone: Code-Eingabe-Seite
        User->>Phone: Gibt "ABCD-1234" ein
        Phone->>SSO: POST user_code
        SSO->>Phone: Login-Seite
        User->>Phone: Credentials
        Phone->>SSO: POST credentials
        SSO->>Phone: "Gerät autorisiert!"
    end

    Device->>SSO: POST /token (device_code)
    SSO->>Device: {access_token, id_token, refresh_token}

    Device->>User: Eingeloggt!
```

## Client Credentials Grant (M2M)

Für Machine-to-Machine-Kommunikation ohne Benutzerinteraktion.

```mermaid
sequenceDiagram
    autonumber
    participant Backend as Backend-Service
    participant SSO as SSO Provider
    participant API as Geschützte API

    Note over Backend: Cronjob / Hintergrund-Task

    Backend->>SSO: POST /token
    Note right of Backend: grant_type=client_credentials<br/>client_id + client_secret<br/>scope=api:read

    SSO->>SSO: Client-Credentials validieren
    SSO->>Backend: {access_token, expires_in, scope}

    Note over Backend: Kein id_token (kein User)<br/>Kein refresh_token (einfach neu anfordern)

    Backend->>API: GET /api/data
    Note right of Backend: Authorization: Bearer {access_token}

    API->>SSO: POST /introspect (Token validieren)
    SSO->>API: {active: true, scope: "api:read", ...}

    API->>Backend: {data: [...]}
```

## Token Introspection (RFC 7662)

Für Resource Server, die eingehende Tokens validieren.

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant API as Resource Server
    participant SSO as SSO Provider

    Client->>API: GET /api/resource
    Note right of Client: Authorization: Bearer {token}

    API->>API: Token aus Header extrahieren

    API->>SSO: POST /introspect
    Note right of API: token={token}<br/>client_id + client_secret

    SSO->>SSO: Token nachschlagen, Ablauf prüfen

    alt Token gültig
        SSO->>API: {active: true, sub: "user123", scope: "read write", exp: ...}
        API->>API: Erforderliche Scopes prüfen
        API->>Client: {data: "..."}
    else Token ungültig/abgelaufen
        SSO->>API: {active: false}
        API->>Client: 401 Unauthorized
    end
```

## Token Refresh

Stille Token-Erneuerung mit Refresh Token.

```mermaid
sequenceDiagram
    autonumber
    participant App as Deine App
    participant SSO as SSO Provider

    Note over App: Access Token abgelaufen oder läuft bald ab

    App->>App: refresh_token aus Session holen

    App->>SSO: POST /token
    Note right of App: grant_type=refresh_token<br/>refresh_token={token}<br/>client_id + client_secret

    SSO->>SSO: Refresh Token validieren

    alt Refresh Token gültig
        SSO->>App: {access_token, id_token, refresh_token, expires_in}
        App->>App: Neue Tokens in Session speichern
        App->>App: TokenRefreshedEvent dispatchen
    else Refresh Token abgelaufen/widerrufen
        SSO->>App: {error: "invalid_grant"}
        App->>App: Session löschen, zum Login weiterleiten
    end
```

## Session Management

SSO-Session-Änderungen erkennen (z.B. Logout in anderer App).

```mermaid
sequenceDiagram
    autonumber
    participant Browser
    participant App as Deine App (JS)
    participant IFrame as Versteckter IFrame
    participant SSO as SSO Provider

    Browser->>App: Seite laden
    App->>IFrame: check_session_iframe laden
    IFrame->>SSO: GET /check-session
    SSO->>IFrame: Session-Monitor-Seite

    loop Alle 5 Sekunden
        App->>IFrame: postMessage("client_id session_state")
        IFrame->>IFrame: session_state mit SSO-Cookie vergleichen

        alt Session unverändert
            IFrame->>App: postMessage("unchanged")
        else Session geändert (Logout woanders)
            IFrame->>App: postMessage("changed")
            App->>Browser: Seite neu laden / Zum Login weiterleiten
        end
    end
```

## Logout-Flows

### RP-Initiated Logout

Benutzer klickt Logout in deiner App.

```mermaid
sequenceDiagram
    autonumber
    participant User as Benutzer
    participant Browser
    participant App as Deine App
    participant SSO as SSO Provider

    User->>Browser: Klickt "Logout"
    Browser->>App: POST /auth/logout (CSRF-Token)

    App->>App: Lokale Session löschen
    App->>App: id_token_hint holen

    App->>Browser: Redirect zu /end-session
    Browser->>SSO: GET /end-session?id_token_hint=...&post_logout_redirect_uri=...

    SSO->>SSO: SSO-Session beenden
    SSO->>SSO: Andere Clients benachrichtigen (Back-Channel)

    SSO->>Browser: Redirect zur post_logout_redirect_uri
    Browser->>App: GET /
    App->>User: Ausgeloggt!
```

### Front-Channel Logout

SSO benachrichtigt deine App via versteckte iframes.

```mermaid
sequenceDiagram
    autonumber
    participant User as Benutzer
    participant Browser
    participant OtherApp as Andere App
    participant SSO as SSO Provider
    participant App as Deine App

    User->>OtherApp: Klickt "Logout"
    OtherApp->>SSO: Logout initiieren

    SSO->>Browser: Logout-Seite mit iframes

    par Alle Clients benachrichtigen
        Browser->>App: GET /auth/frontchannel-logout?sid=...
        App->>App: Session für sid löschen
        App->>Browser: 200 OK
    and Andere Clients
        Browser->>OtherApp: GET /frontchannel-logout
    end

    SSO->>Browser: Redirect zur Ursprungs-App
```

### Back-Channel Logout

SSO benachrichtigt deine App via Server-to-Server HTTP.

```mermaid
sequenceDiagram
    autonumber
    participant User as Benutzer
    participant OtherApp as Andere App
    participant SSO as SSO Provider
    participant App as Deine App

    User->>OtherApp: Klickt "Logout"
    OtherApp->>SSO: Logout initiieren

    SSO->>SSO: SSO-Session beenden

    par Server-to-Server-Benachrichtigungen
        SSO->>App: POST /auth/backchannel-logout
        Note right of SSO: logout_token (JWT mit sid/sub)
        App->>App: logout_token validieren
        App->>App: Session für sid/sub löschen
        App->>SSO: 200 OK
    and Andere Clients
        SSO->>OtherApp: POST /backchannel-logout
    end

    SSO->>User: Überall ausgeloggt
```

## Komplette Flow-Übersicht

```mermaid
flowchart TD
    Start([Benutzer will auf App zugreifen])

    Start --> Check{Authentifiziert?}

    Check -->|Nein| LoginChoice{Login-Methode?}

    LoginChoice -->|Browser| AuthCode[Authorization Code Flow]
    LoginChoice -->|CLI/Gerät| DeviceCode[Device Code Flow]
    LoginChoice -->|M2M/Backend| ClientCreds[Client Credentials]

    AuthCode --> Tokens[Tokens empfangen]
    DeviceCode --> Tokens
    ClientCreds --> Tokens

    Tokens --> Store[In Session speichern]
    Store --> Check

    Check -->|Ja| Access[Auf geschützte Ressource zugreifen]

    Access --> Expired{Token abgelaufen?}
    Expired -->|Ja| Refresh[Token Refresh]
    Refresh -->|Erfolg| Access
    Refresh -->|Fehlgeschlagen| LoginChoice

    Expired -->|Nein| Resource[Ressource zurückgeben]

    Resource --> Logout{Logout?}
    Logout -->|Ja| EndSession[Session beenden]
    EndSession -->|RP-Initiated| SSO[SSO Logout]
    EndSession -->|Front-Channel| Clear1[Session löschen]
    EndSession -->|Back-Channel| Clear2[Session löschen]

    SSO --> Start
    Clear1 --> Start
    Clear2 --> Start

    Logout -->|Nein| Continue[App weiter nutzen]
    Continue --> Access
```
