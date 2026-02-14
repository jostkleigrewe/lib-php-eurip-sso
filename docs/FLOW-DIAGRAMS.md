# OIDC Flow Diagrams

Visual sequence diagrams for all supported authentication flows.

## Authorization Code Flow (with PKCE)

The standard browser-based login flow.

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Browser
    participant App as Your App
    participant SSO as SSO Provider

    User->>Browser: Clicks "Login"
    Browser->>App: GET /auth/login

    Note over App: Generate state, nonce, PKCE verifier
    App->>App: Store in session

    App->>Browser: Redirect to /authorize
    Browser->>SSO: GET /authorize?client_id=...&code_challenge=...

    SSO->>Browser: Login page
    User->>Browser: Enter credentials
    Browser->>SSO: POST credentials

    alt Consent required
        SSO->>Browser: Consent page
        User->>Browser: Approve
        Browser->>SSO: POST consent
    end

    SSO->>Browser: Redirect to callback
    Browser->>App: GET /auth/callback?code=...&state=...

    Note over App: Validate state
    App->>SSO: POST /token (code + PKCE verifier)
    SSO->>App: {access_token, id_token, refresh_token}

    Note over App: Validate JWT signature & claims
    App->>App: Create/update user, store tokens

    App->>Browser: Redirect to target page
    Browser->>User: Logged in!
```

## Device Authorization Grant (RFC 8628)

For devices without browser (CLI, Smart TV, IoT).

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Device as CLI / Device
    participant Phone as User's Phone
    participant SSO as SSO Provider

    Device->>SSO: POST /device/authorize
    SSO->>Device: {device_code, user_code, verification_uri}

    Device->>User: "Go to: https://sso/device"
    Device->>User: "Enter code: ABCD-1234"

    par Device polls for token
        loop Every 5 seconds
            Device->>SSO: POST /token (device_code)
            SSO->>Device: {error: "authorization_pending"}
        end
    and User authorizes
        User->>Phone: Opens verification_uri
        Phone->>SSO: GET /device
        SSO->>Phone: Enter code page
        User->>Phone: Enters "ABCD-1234"
        Phone->>SSO: POST user_code
        SSO->>Phone: Login page
        User->>Phone: Credentials
        Phone->>SSO: POST credentials
        SSO->>Phone: "Device authorized!"
    end

    Device->>SSO: POST /token (device_code)
    SSO->>Device: {access_token, id_token, refresh_token}

    Device->>User: Logged in!
```

## Client Credentials Grant (M2M)

For machine-to-machine communication without user interaction.

```mermaid
sequenceDiagram
    autonumber
    participant Backend as Backend Service
    participant SSO as SSO Provider
    participant API as Protected API

    Note over Backend: Scheduled job / background task

    Backend->>SSO: POST /token
    Note right of Backend: grant_type=client_credentials<br/>client_id + client_secret<br/>scope=api:read

    SSO->>SSO: Validate client credentials
    SSO->>Backend: {access_token, expires_in, scope}

    Note over Backend: No id_token (no user)<br/>No refresh_token (just request new)

    Backend->>API: GET /api/data
    Note right of Backend: Authorization: Bearer {access_token}

    API->>SSO: POST /introspect (validate token)
    SSO->>API: {active: true, scope: "api:read", ...}

    API->>Backend: {data: [...]}
```

## Token Introspection (RFC 7662)

For resource servers to validate incoming tokens.

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant API as Resource Server
    participant SSO as SSO Provider

    Client->>API: GET /api/resource
    Note right of Client: Authorization: Bearer {token}

    API->>API: Extract token from header

    API->>SSO: POST /introspect
    Note right of API: token={token}<br/>client_id + client_secret

    SSO->>SSO: Lookup token, check expiry

    alt Token valid
        SSO->>API: {active: true, sub: "user123", scope: "read write", exp: ...}
        API->>API: Check required scopes
        API->>Client: {data: "..."}
    else Token invalid/expired
        SSO->>API: {active: false}
        API->>Client: 401 Unauthorized
    end
```

## Token Refresh

Silent token renewal using refresh token.

```mermaid
sequenceDiagram
    autonumber
    participant App as Your App
    participant SSO as SSO Provider

    Note over App: Access token expired or expiring soon

    App->>App: Get refresh_token from session

    App->>SSO: POST /token
    Note right of App: grant_type=refresh_token<br/>refresh_token={token}<br/>client_id + client_secret

    SSO->>SSO: Validate refresh token

    alt Refresh token valid
        SSO->>App: {access_token, id_token, refresh_token, expires_in}
        App->>App: Store new tokens in session
        App->>App: Dispatch TokenRefreshedEvent
    else Refresh token expired/revoked
        SSO->>App: {error: "invalid_grant"}
        App->>App: Clear session, redirect to login
    end
```

## Session Management

Detecting SSO session changes (e.g., logout in another app).

```mermaid
sequenceDiagram
    autonumber
    participant Browser
    participant App as Your App (JS)
    participant IFrame as Hidden IFrame
    participant SSO as SSO Provider

    Browser->>App: Page load
    App->>IFrame: Load check_session_iframe
    IFrame->>SSO: GET /check-session
    SSO->>IFrame: Session monitor page

    loop Every 5 seconds
        App->>IFrame: postMessage("client_id session_state")
        IFrame->>IFrame: Compare session_state with SSO cookie

        alt Session unchanged
            IFrame->>App: postMessage("unchanged")
        else Session changed (logout elsewhere)
            IFrame->>App: postMessage("changed")
            App->>Browser: Reload page / Redirect to login
        end
    end
```

## Logout Flows

### RP-Initiated Logout

User clicks logout in your app.

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Browser
    participant App as Your App
    participant SSO as SSO Provider

    User->>Browser: Clicks "Logout"
    Browser->>App: POST /auth/logout (CSRF token)

    App->>App: Clear local session
    App->>App: Get id_token_hint

    App->>Browser: Redirect to /end-session
    Browser->>SSO: GET /end-session?id_token_hint=...&post_logout_redirect_uri=...

    SSO->>SSO: End SSO session
    SSO->>SSO: Notify other clients (back-channel)

    SSO->>Browser: Redirect to post_logout_redirect_uri
    Browser->>App: GET /
    App->>User: Logged out!
```

### Front-Channel Logout

SSO notifies your app via hidden iframes.

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Browser
    participant OtherApp as Other App
    participant SSO as SSO Provider
    participant App as Your App

    User->>OtherApp: Clicks "Logout"
    OtherApp->>SSO: Initiate logout

    SSO->>Browser: Logout page with iframes

    par Notify all clients
        Browser->>App: GET /auth/frontchannel-logout?sid=...
        App->>App: Clear session for sid
        App->>Browser: 200 OK
    and Other clients
        Browser->>OtherApp: GET /frontchannel-logout
    end

    SSO->>Browser: Redirect to origin app
```

### Back-Channel Logout

SSO notifies your app via server-to-server HTTP.

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant OtherApp as Other App
    participant SSO as SSO Provider
    participant App as Your App

    User->>OtherApp: Clicks "Logout"
    OtherApp->>SSO: Initiate logout

    SSO->>SSO: End SSO session

    par Server-to-server notifications
        SSO->>App: POST /auth/backchannel-logout
        Note right of SSO: logout_token (JWT with sid/sub)
        App->>App: Validate logout_token
        App->>App: Clear session for sid/sub
        App->>SSO: 200 OK
    and Other clients
        SSO->>OtherApp: POST /backchannel-logout
    end

    SSO->>User: Logged out everywhere
```

## Complete Flow Overview

```mermaid
flowchart TD
    Start([User wants to access app])

    Start --> Check{Authenticated?}

    Check -->|No| LoginChoice{Login method?}

    LoginChoice -->|Browser| AuthCode[Authorization Code Flow]
    LoginChoice -->|CLI/Device| DeviceCode[Device Code Flow]
    LoginChoice -->|M2M/Backend| ClientCreds[Client Credentials]

    AuthCode --> Tokens[Receive Tokens]
    DeviceCode --> Tokens
    ClientCreds --> Tokens

    Tokens --> Store[Store in Session]
    Store --> Check

    Check -->|Yes| Access[Access Protected Resource]

    Access --> Expired{Token expired?}
    Expired -->|Yes| Refresh[Refresh Token]
    Refresh -->|Success| Access
    Refresh -->|Failed| LoginChoice

    Expired -->|No| Resource[Return Resource]

    Resource --> Logout{Logout?}
    Logout -->|Yes| EndSession[End Session]
    EndSession -->|RP-Initiated| SSO[SSO Logout]
    EndSession -->|Front-Channel| Clear1[Clear Session]
    EndSession -->|Back-Channel| Clear2[Clear Session]

    SSO --> Start
    Clear1 --> Start
    Clear2 --> Start

    Logout -->|No| Continue[Continue using app]
    Continue --> Access
```
