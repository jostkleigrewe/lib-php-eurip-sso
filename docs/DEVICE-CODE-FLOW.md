# Device Code Flow (RFC 8628)

🇩🇪 [Deutsche Version](DEVICE-CODE-FLOW.de.md)

## Overview

The Device Authorization Grant (RFC 8628) enables authentication on devices that either lack a browser or have limited input capabilities. Common use cases include:

- **CLI Tools** - Command-line applications
- **Smart TVs** - TV apps without keyboard
- **IoT Devices** - Devices with display but no browser
- **Game Consoles** - Login without typing passwords

## How It Works

```
┌─────────────────┐                              ┌─────────────────┐
│  Device/CLI     │                              │  OIDC Provider  │
│  (Your App)     │                              │  (SSO Server)   │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  1. POST /oidc/device/authorize                │
         │     client_id, scope                           │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  2. Response:                                  │
         │     device_code, user_code,                    │
         │     verification_uri, expires_in               │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         │  3. Display to user:                           │
         │     "Open: https://sso.example.com/device"     │
         │     "Enter code: ABCD-EFGH"                    │
         │                                                │
         │                    ┌─────────────────┐         │
         │                    │  User's Browser │         │
         │                    │  (e.g., Phone)  │         │
         │                    └────────┬────────┘         │
         │                             │                  │
         │                             │ 4. User opens    │
         │                             │    URL, enters   │
         │                             │    code, logs in │
         │                             │ ────────────────►│
         │                             │                  │
         │  5. Poll: POST /oidc/token                     │
         │     grant_type=device_code, device_code        │
         │ ──────────────────────────────────────────────►│
         │                                                │
         │  6a. "authorization_pending" (keep polling)    │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         │  ... (repeat every 5 seconds) ...              │
         │                                                │
         │  6b. Success: access_token, refresh_token      │
         │ ◄──────────────────────────────────────────────│
         │                                                │
         ▼                                                ▼
```

## Prerequisites

### Provider Requirements

Your OIDC Provider must support RFC 8628. Check the discovery document:

```bash
curl https://sso.example.com/.well-known/openid-configuration | jq '.device_authorization_endpoint'
```

If the response is `null`, the provider doesn't support Device Code Flow.

### Bundle Configuration

No special configuration needed. The bundle automatically detects `device_authorization_endpoint` from discovery.

## Usage

### CLI Command (Recommended for CLI Apps)

```bash
# Interactive login with visual feedback
bin/console eurip:sso:device-login

# With custom scopes
bin/console eurip:sso:device-login --scopes="openid,profile,email,roles"

# Output only the access token (for scripting)
ACCESS_TOKEN=$(bin/console eurip:sso:device-login --output-token)
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://api.example.com/me

# Full JSON response
bin/console eurip:sso:device-login --output-json > tokens.json
```

### Programmatic Usage (Blocking)

```php
use Jostkleigrewe\Sso\Client\OidcClient;

// Inject or create OidcClient
public function login(OidcClient $oidcClient): void
{
    // 1. Request device code
    $deviceCode = $oidcClient->requestDeviceCode(['openid', 'profile', 'email']);

    // 2. Display instructions to user
    $this->output->writeln("To sign in, open: {$deviceCode->verificationUri}");
    $this->output->writeln("Enter code: {$deviceCode->getFormattedUserCode()}");

    // Optional: Show the complete URL (with code pre-filled)
    if ($deviceCode->verificationUriComplete !== null) {
        $this->output->writeln("Or open directly: {$deviceCode->verificationUriComplete}");
    }

    // 3. Wait for authorization (blocking)
    $tokenResponse = $oidcClient->awaitDeviceToken(
        $deviceCode,
        // Optional: Progress callback
        fn(int $attempt, int $interval) => $this->output->write('.'),
    );

    // 4. Use the tokens
    $accessToken = $tokenResponse->accessToken;
    $refreshToken = $tokenResponse->refreshToken; // May be null
    $idToken = $tokenResponse->idToken;           // May be null
}
```

### Programmatic Usage (Manual Polling)

For more control over the polling process:

```php
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\DTO\DeviceCodePollResult;

public function loginWithManualPolling(OidcClient $oidcClient): void
{
    $deviceCode = $oidcClient->requestDeviceCode(['openid', 'profile']);

    $this->displayInstructions($deviceCode);

    $interval = $deviceCode->interval; // Usually 5 seconds
    $startTime = time();
    $maxWaitTime = $deviceCode->expiresIn;

    while (true) {
        // Check timeout
        if ((time() - $startTime) > $maxWaitTime) {
            throw new \RuntimeException('Device code expired');
        }

        // Wait before polling (required by RFC 8628)
        sleep($interval);

        // Poll for token
        $result = $oidcClient->pollDeviceToken($deviceCode->deviceCode, $interval);

        switch ($result->status) {
            case DeviceCodePollResult::STATUS_SUCCESS:
                // Success! Token received
                $this->handleSuccess($result->tokenResponse);
                return;

            case DeviceCodePollResult::STATUS_PENDING:
                // User hasn't authorized yet, keep polling
                $this->output->write('.');
                break;

            case DeviceCodePollResult::STATUS_SLOW_DOWN:
                // Polling too fast, increase interval
                $interval = $result->getRecommendedInterval($interval);
                $this->output->writeln("Slowing down to {$interval}s interval");
                break;

            case DeviceCodePollResult::STATUS_ACCESS_DENIED:
                // User denied the request
                throw new \RuntimeException('User denied authorization');

            case DeviceCodePollResult::STATUS_EXPIRED:
                // Device code expired
                throw new \RuntimeException('Device code expired');
        }
    }
}
```

## API Reference

### DeviceCodeResponse

Returned by `requestDeviceCode()`:

| Property | Type | Description |
|----------|------|-------------|
| `deviceCode` | `string` | The device verification code (don't show to user) |
| `userCode` | `string` | The code the user must enter (e.g., "ABCDEFGH") |
| `verificationUri` | `string` | URL the user should open |
| `verificationUriComplete` | `?string` | URL with code pre-filled (optional) |
| `expiresIn` | `int` | Seconds until the device code expires |
| `interval` | `int` | Minimum polling interval in seconds (default: 5) |

**Helper Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `getFormattedUserCode()` | `string` | Formatted code (e.g., "ABCD-EFGH") |
| `getBestVerificationUri()` | `string` | Returns `verificationUriComplete` if available |
| `getExpiresAt()` | `DateTimeImmutable` | Expiration timestamp |
| `isExpired()` | `bool` | Whether the code has expired |

### DeviceCodePollResult

Returned by `pollDeviceToken()`:

| Property | Type | Description |
|----------|------|-------------|
| `status` | `string` | One of the STATUS_* constants |
| `tokenResponse` | `?TokenResponse` | Tokens on success, null otherwise |
| `newInterval` | `?int` | New polling interval (on slow_down) |
| `errorDescription` | `?string` | Error message (on error) |

**Status Constants:**

| Constant | Meaning | Action |
|----------|---------|--------|
| `STATUS_SUCCESS` | User authorized, tokens received | Stop polling, use tokens |
| `STATUS_PENDING` | User hasn't authorized yet | Continue polling |
| `STATUS_SLOW_DOWN` | Polling too fast | Increase interval, continue |
| `STATUS_ACCESS_DENIED` | User denied authorization | Stop, show error |
| `STATUS_EXPIRED` | Device code expired | Stop, request new code |

**Helper Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `isSuccess()` | `bool` | True if tokens received |
| `shouldContinuePolling()` | `bool` | True if pending or slow_down |
| `isError()` | `bool` | True if access_denied or expired |
| `shouldSlowDown()` | `bool` | True if interval should increase |
| `getRecommendedInterval(int $current)` | `int` | Next interval to use |

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `OidcProtocolException: No device_authorization_endpoint configured` | Provider doesn't support RFC 8628 | Use standard browser-based flow |
| `TokenExchangeFailedException: access_denied` | User clicked "Deny" | Inform user, offer retry |
| `TokenExchangeFailedException: expired_token` | User didn't authorize in time | Request new device code |
| `TokenExchangeFailedException: timeout` | Polling loop exceeded max attempts | Request new device code |

### Exception Handling Example

```php
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;

try {
    $deviceCode = $oidcClient->requestDeviceCode(['openid']);
    $tokens = $oidcClient->awaitDeviceToken($deviceCode);
} catch (OidcProtocolException $e) {
    // Provider doesn't support device flow
    $this->logger->error('Device flow not supported', ['error' => $e->getMessage()]);
    $this->fallbackToBrowserFlow();
} catch (TokenExchangeFailedException $e) {
    match ($e->getErrorCode()) {
        'access_denied' => $this->output->error('You denied the authorization request.'),
        'expired_token' => $this->output->warning('The code expired. Please try again.'),
        'timeout' => $this->output->warning('Timed out waiting for authorization.'),
        default => $this->output->error("Authentication failed: {$e->getMessage()}"),
    };
}
```

## Timeouts and Intervals

### Default Values

| Parameter | Default | Description |
|-----------|---------|-------------|
| Device code expiration | 600s (10 min) | Time user has to authorize |
| Polling interval | 5s | Minimum time between polls |
| Slow-down increment | +5s | Added to interval on slow_down |

### Best Practices

1. **Always respect the interval** - RFC 8628 requires waiting at least `interval` seconds between polls
2. **Handle slow_down** - If you poll too fast, the provider will return `slow_down`
3. **Show remaining time** - Help users understand urgency
4. **Allow cancellation** - Let users abort the process (Ctrl+C in CLI)

## Security Considerations

1. **Device Code is secret** - Only show `userCode` to the user, never `deviceCode`
2. **HTTPS required** - All endpoints must use HTTPS in production
3. **Short-lived codes** - Device codes expire quickly (usually 10-15 minutes)
4. **One-time use** - Each device code can only be used once

## Troubleshooting

### "No device_authorization_endpoint configured"

**Cause:** The OIDC Provider doesn't expose a `device_authorization_endpoint` in its discovery document.

**Solution:**
1. Check if your provider supports RFC 8628
2. Verify the discovery document: `curl https://your-sso/.well-known/openid-configuration | jq '.device_authorization_endpoint'`
3. If not supported, use the standard browser-based flow instead

### "authorization_pending" forever

**Cause:** User hasn't completed authorization in the browser.

**Checklist:**
1. Is the `verification_uri` correct and accessible?
2. Did the user enter the correct `user_code`?
3. Did the user complete the login and consent?
4. Is there a network issue between user's browser and SSO?

### "slow_down" responses

**Cause:** Polling too frequently.

**Solution:** The bundle handles this automatically. If you're implementing manual polling, always use `$result->getRecommendedInterval()`.

### "expired_token" too quickly

**Cause:** Device code expired before user could authorize.

**Solutions:**
1. Show clear instructions immediately
2. Display countdown timer
3. Consider using `verification_uri_complete` for easier mobile entry

## References

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 for TV and Limited-Input Device Applications](https://developers.google.com/identity/protocols/oauth2/limited-input-device)
