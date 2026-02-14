# Sequenzdiagramme - OIDC Flows

DE: Visualisierung der OIDC-Flows im Bundle.
EN: Visualization of OIDC flows in the bundle.

---

## 1. Authorization Code Flow mit PKCE

DE: Standard-Login-Flow (OpenID Connect Core 1.0 + PKCE).
EN: Standard login flow (OpenID Connect Core 1.0 + PKCE).

```mermaid
sequenceDiagram
    participant User as Browser
    participant App as Client-App
    participant Bundle as EURIP SSO Bundle
    participant IdP as SSO Provider

    User->>App: GET /protected-page
    App->>User: Redirect to /auth/login

    User->>Bundle: GET /auth/login
    Note over Bundle: Generate state, nonce, PKCE verifier
    Bundle->>Bundle: Store in session
    Bundle->>User: Redirect to IdP /authorize

    User->>IdP: GET /oidc/authorize
    Note over IdP: Show login form
    IdP->>User: Login page
    User->>IdP: Submit credentials
    Note over IdP: Validate, generate code
    IdP->>User: Redirect to /auth/callback?code=xxx&state=xxx

    User->>Bundle: GET /auth/callback?code=xxx&state=xxx
    Note over Bundle: Validate state
    Bundle->>IdP: POST /oidc/token (code, verifier)
    IdP->>Bundle: TokenResponse (id_token, access_token)
    Note over Bundle: Validate JWT signature + claims

    alt User exists
        Bundle->>Bundle: Sync user data
        Bundle-->>Bundle: Dispatch OidcUserUpdatedEvent
    else New user
        Bundle->>Bundle: Create user
        Bundle-->>Bundle: Dispatch OidcUserCreatedEvent
    end

    Bundle-->>Bundle: Dispatch OidcLoginSuccessEvent
    Bundle->>User: Redirect to target path
    User->>App: GET /protected-page
    App->>User: Protected content
```

---

## 2. Logout Flow (RP-Initiated)

DE: Logout vom Client initiiert (OpenID Connect RP-Initiated Logout 1.0).
EN: Logout initiated from client (OpenID Connect RP-Initiated Logout 1.0).

```mermaid
sequenceDiagram
    participant User as Browser
    participant Bundle as EURIP SSO Bundle
    participant IdP as SSO Provider

    User->>Bundle: GET /auth/logout
    Bundle-->>Bundle: Dispatch OidcPreLogoutEvent

    alt Event has custom response
        Bundle->>User: Custom response
    else Skip SSO logout
        Bundle->>Bundle: Invalidate local session
        Bundle->>User: Redirect to after_logout
    else Normal flow
        Bundle->>Bundle: Get id_token from session
        Bundle->>Bundle: Invalidate local session
        Bundle->>User: Redirect to IdP /end-session
        User->>IdP: GET /oidc/end-session?id_token_hint=xxx
        IdP->>IdP: Invalidate SSO session
        IdP->>User: Redirect to post_logout_redirect_uri
        User->>Bundle: Follow redirect
    end
```

---

## 3. Back-Channel Logout

DE: Server-zu-Server Logout (OpenID Connect Back-Channel Logout 1.0).
EN: Server-to-server logout (OpenID Connect Back-Channel Logout 1.0).

```mermaid
sequenceDiagram
    participant Admin as Admin/User
    participant IdP as SSO Provider
    participant Bundle as EURIP SSO Bundle
    participant Listener as App Listener

    Admin->>IdP: Trigger logout (admin action or timeout)
    Note over IdP: Generate logout token (JWT)
    IdP->>Bundle: POST /auth/backchannel-logout<br/>logout_token=xxx

    Note over Bundle: Validate JWT signature
    Note over Bundle: Validate events claim
    Note over Bundle: Validate iss, aud, exp
    Note over Bundle: Extract sub, sid

    Bundle-->>Listener: Dispatch OidcBackchannelLogoutEvent

    alt Listener handles
        Listener->>Listener: Invalidate sessions for user
        Listener->>Bundle: markHandled()
    else No listener
        Note over Bundle: Log warning (but still OK)
    end

    Bundle->>IdP: HTTP 200 OK
```

---

## 4. Front-Channel Logout

DE: Browser-basierter Logout via Iframe (OpenID Connect Front-Channel Logout 1.0).
EN: Browser-based logout via iframe (OpenID Connect Front-Channel Logout 1.0).

```mermaid
sequenceDiagram
    participant User as Browser
    participant IdP as SSO Provider
    participant Iframe as Hidden Iframe
    participant Bundle as EURIP SSO Bundle

    User->>IdP: Logout at IdP
    IdP->>IdP: Get all registered RPs
    IdP->>User: Logout page with hidden iframes

    par For each RP
        User->>Iframe: Load /auth/frontchannel-logout?iss=xxx&sid=xxx
        Iframe->>Bundle: GET /auth/frontchannel-logout?iss=xxx&sid=xxx
        Note over Bundle: Validate issuer
        Bundle-->>Bundle: Dispatch OidcFrontchannelLogoutEvent
        Bundle->>Bundle: Invalidate session
        Bundle->>Iframe: HTML response (no X-Frame-Options)
    end

    IdP->>User: Logout complete page
```

---

## 5. Token Refresh Flow

DE: Access Token erneuern mit Refresh Token.
EN: Renew access token using refresh token.

```mermaid
sequenceDiagram
    participant App as Client-App
    participant Bundle as EURIP SSO Bundle
    participant IdP as SSO Provider

    App->>Bundle: API call (access_token expired)
    Bundle->>Bundle: Check token expiry

    alt Has refresh_token
        Bundle->>IdP: POST /oidc/token<br/>grant_type=refresh_token
        IdP->>Bundle: New TokenResponse
        Bundle->>Bundle: Update stored tokens
        Bundle-->>Bundle: Dispatch OidcTokenRefreshedEvent
        Bundle->>App: Continue with new token
    else No refresh_token
        Bundle->>App: Throw NotAuthenticatedException
    end
```

---

## 6. Session Management (Check Session)

DE: Browser prüft Session-Status via Iframe (OpenID Connect Session Management 1.0).
EN: Browser checks session status via iframe (OpenID Connect Session Management 1.0).

```mermaid
sequenceDiagram
    participant App as Client-App (JS)
    participant Iframe as OP Iframe
    participant IdP as SSO Provider

    Note over App: Load check_session_iframe from IdP
    App->>Iframe: Load /oidc/check-session

    loop Every N seconds
        App->>Iframe: postMessage(client_id + " " + session_state)
        Iframe->>Iframe: Calculate hash from origin + client_id + cookie

        alt Session unchanged
            Iframe->>App: postMessage("unchanged")
        else Session changed
            Iframe->>App: postMessage("changed")
            App->>App: Trigger re-authentication or logout
        else Error
            Iframe->>App: postMessage("error")
        end
    end
```

---

## Event-Flow Übersicht

DE: Zusammenfassung aller Events im Bundle.
EN: Summary of all events in the bundle.

```mermaid
flowchart TD
    subgraph Login
        A[GET /auth/login] --> B[OidcPreLoginEvent]
        B --> C{Custom Response?}
        C -->|Yes| D[Return Response]
        C -->|No| E[Redirect to IdP]
        E --> F[GET /auth/callback]
        F --> G{User exists?}
        G -->|No| H[OidcUserCreatedEvent]
        G -->|Yes| I[OidcUserUpdatedEvent]
        H --> J[OidcLoginSuccessEvent]
        I --> J
        J --> K{Custom Response?}
        K -->|Yes| D
        K -->|No| L[Redirect to target]
    end

    subgraph Logout
        M[GET /auth/logout] --> N[OidcPreLogoutEvent]
        N --> O{Skip SSO?}
        O -->|Yes| P[Local logout only]
        O -->|No| Q[SSO logout]
    end

    subgraph "Server Logout"
        R[POST /backchannel-logout] --> S[OidcBackchannelLogoutEvent]
        T[GET /frontchannel-logout] --> U[OidcFrontchannelLogoutEvent]
    end

    subgraph "Token Refresh"
        V[Token expired] --> W[Refresh token]
        W --> X[OidcTokenRefreshedEvent]
    end
```

---

## Legende

| Symbol | Bedeutung |
|--------|-----------|
| `-->>` | Event dispatch (async) |
| `-->` | Synchroner Aufruf |
| `Note` | Wichtige Verarbeitung |
| `alt/else` | Bedingte Verzweigung |
| `par` | Parallele Ausführung |
| `loop` | Wiederholung |
