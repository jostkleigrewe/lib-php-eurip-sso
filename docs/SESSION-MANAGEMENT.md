# OIDC Session Management

This bundle supports [OIDC Session Management](https://openid.net/specs/openid-connect-session-1_0.html), which allows your application to detect when the user's SSO session has changed (e.g., logout in another application).

## How It Works

```
┌─────────────────┐                          ┌─────────────────┐
│  Your App       │                          │  SSO Provider   │
│  (Browser)      │                          │                 │
└────────┬────────┘                          └────────┬────────┘
         │                                            │
         │  Hidden iframe loads check_session_iframe  │
         │ ──────────────────────────────────────────►│
         │                                            │
         │  Every N seconds: postMessage              │
         │  "client_id session_state"                 │
         │ ──────────────────────────────────────────►│
         │                                            │
         │  Response: "changed" | "unchanged"         │
         │ ◄──────────────────────────────────────────│
         │                                            │
    ┌────┴────┐                                       │
    │ If      │  → Page reload / Logout / Custom      │
    │"changed"│     action                            │
    └─────────┘                                       │
```

## Prerequisites

1. **SSO Provider must support Session Management**
   - The provider must expose `check_session_iframe` in the discovery document
   - EURIP SSO already supports this

2. **Session State must be stored**
   - The `session_state` parameter from the authorization response must be saved
   - This bundle does this automatically

## Quick Start

Add the session monitor component to your base template:

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
<head>
    {# ... #}
</head>
<body>
    {# ... your content ... #}

    {# Add before closing body tag #}
    {% include '@EuripSso/components/SessionMonitor.html.twig' %}
</body>
</html>
```

That's it! The component will:
- Load a hidden iframe pointing to the SSO provider's `check_session_iframe`
- Poll every 5 seconds (configurable)
- Reload the page if the session state changes

## Configuration Options

### Custom Polling Interval

```twig
{% include '@EuripSso/components/SessionMonitor.html.twig' with {
    interval: 10000
} %}
```

### Custom Change Handler

Instead of reloading, redirect to logout:

```twig
{% include '@EuripSso/components/SessionMonitor.html.twig' with {
    onChanged: 'window.location.href = "/logout"'
} %}
```

Or show a notification:

```twig
{% include '@EuripSso/components/SessionMonitor.html.twig' with {
    onChanged: 'alert("Your session has expired. Please log in again.")'
} %}
```

## Twig Functions

### `sso_supports_session_management()`

Returns `true` if session management is available:

```twig
{% if sso_supports_session_management() %}
    <p>Session monitoring is active</p>
{% endif %}
```

### `sso_session_management_config(interval)`

Returns the configuration needed for session management:

```twig
{% set config = sso_session_management_config(5000) %}
{# Returns: {checkSessionIframe: "...", clientId: "...", sessionState: "...", interval: 5000} #}
```

## Manual JavaScript Integration

If you prefer to handle session management yourself:

```javascript
// Get config from Twig
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
                console.log('Session changed!');
                // Your custom logic here
            }
        }
    });
}
```

## Troubleshooting

### Session monitoring not working

1. **Check if supported:**
   ```twig
   {{ dump(sso_supports_session_management()) }}
   ```

2. **Check config:**
   ```twig
   {{ dump(sso_session_management_config()) }}
   ```

3. **Verify `check_session_iframe` in discovery:**
   ```bash
   curl https://your-sso/.well-known/openid-configuration | jq .check_session_iframe
   ```

### Cross-origin issues

The `check_session_iframe` uses `postMessage` which requires proper CORS setup. Ensure:
- The SSO provider allows your domain
- No `X-Frame-Options: DENY` headers block the iframe

## Security Considerations

- The `session_state` is not sensitive - it's a hash of the session
- The iframe only receives "changed"/"unchanged"/"error" responses
- No tokens or user data are exchanged via postMessage
