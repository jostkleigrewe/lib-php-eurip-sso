# Upgrade Guide

## Upgrading from 0.2.x to 0.3.0

Version 0.3.0 is a major refactoring release with significant breaking changes. This guide helps you migrate your application.

### Requirements Changed

```diff
- PHP 8.2+
+ PHP 8.4+
```

### Configuration Changes

Remove deprecated config options:

```yaml
# config/packages/eurip_sso.yaml

eurip_sso:
    # REMOVE these options (no longer exist):
    # controller:
    #     enabled: true           # Controllers are always active now
    # client_services:
    #     enabled: true           # Services are always registered now
    #     store_access_token: true
    # authenticator:
    #     callback_route: ...     # Use routes.callback instead
    #     login_path: ...         # Use routes.login instead
    #     default_target_path: ...# Use routes.after_login instead

    # KEEP/UPDATE these:
    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        after_login: /                    # was authenticator.default_target_path
        logout_confirm: /auth/logout/confirm  # NEW: optional GET logout page
```

### Service Injection Changes

Replace service aliases with FQCN:

```php
// Before (0.2.x)
public function __construct(
    #[Autowire('@eurip_sso.facade')] EuripSsoFacade $facade,
    #[Autowire('@eurip_sso.claims')] $claims,
)

// After (0.3.0)
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoAuthorizationService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoApiClient;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;

public function __construct(
    private readonly EuripSsoClaimsService $claimsService,
    private readonly EuripSsoAuthorizationService $authService,
    // Direct injection, no aliases needed
)
```

### EuripSsoFacade Removed

The facade class has been removed. Inject services directly:

```php
// Before (0.2.x)
$facade->getClaims()->getEmail();
$facade->getAuth()->hasRole('ROLE_ADMIN');
$facade->getTokenStorage()->getAccessToken();

// After (0.3.0)
$this->claimsService->getEmail();
$this->authorizationService->hasRole('ROLE_ADMIN');
$this->tokenStorage->getAccessToken();
```

### Event Listener Changes

Events are now dispatched by class, not by string constant:

```php
// Before (0.2.x)
use Jostkleigrewe\Sso\Bundle\OidcConstants;

#[AsEventListener(event: OidcConstants::EVENT_LOGIN_SUCCESS)]
public function onLoginSuccess(OidcLoginSuccessEvent $event): void

// After (0.3.0)
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;

#[AsEventListener]  // No event: parameter needed!
public function onLoginSuccess(OidcLoginSuccessEvent $event): void
```

Or with `__invoke()`:

```php
// After (0.3.0) - recommended pattern
#[AsEventListener]
final class LoginSuccessListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // Event class inferred from type hint
    }
}
```

### OidcConstants Changes

Changed from interface to final class:

```php
// Before (0.2.x)
class MyService implements OidcConstants
{
    public function foo(): void
    {
        $key = self::SESSION_STATE;  // Via interface
    }
}

// After (0.3.0)
use Jostkleigrewe\Sso\Bundle\OidcConstants;

final class MyService
{
    public function foo(): void
    {
        $key = OidcConstants::SESSION_STATE;  // Direct reference
    }
}
```

Removed constants:
- `OidcConstants::EVENT_*` - Use class-based event dispatch
- Event class `::NAME` constants - Use class-based event dispatch

### OidcClient Changes

If you use `OidcClient` directly (not via the bundle):

```php
// Before (0.2.x)
$client = OidcClient::fromDiscovery($issuerUrl, $httpClient, $requestFactory);
$client->preloadJwks();

// After (0.3.0)
use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;

// Option 1: Use factory (recommended)
$client = $factory->create();

// Option 2: Manual construction
$jwtVerifier = new JwtVerifier(
    $config->jwksUri,
    $httpClient,
    $requestFactory,
    $logger,
    $cache,
    $cacheKey,
);
$client = new OidcClient($config, $httpClient, $requestFactory, $streamFactory, $jwtVerifier);

// JWKS methods moved to JwtVerifier
$jwtVerifier->fetchAndCacheJwks();
$jwtVerifier->invalidateJwksCache();
```

### Controller Changes

The monolithic `OidcController` has been split:

| Before (0.2.x) | After (0.3.0) |
|----------------|---------------|
| `OidcController::login()` | `AuthenticationController::login()` |
| `OidcController::callback()` | `AuthenticationController::callback()` |
| `OidcController::logout()` | `AuthenticationController::logout()` |
| `OidcController::profile()` | `ProfileController::profile()` |
| `OidcController::debug()` | `DiagnosticsController::debug()` |
| `OidcController::test()` | `DiagnosticsController::test()` |

Route names remain unchanged (`eurip_sso_login`, `eurip_sso_callback`, etc.).

### Route Loader Removed

`OidcRouteLoader` has been removed. Routes are now registered via `#[Route]` attributes on controllers. If you were extending the route loader, use Symfony's standard routing instead.

### New Features Available

After upgrading, you can use:

**Twig Functions:**
```twig
{% if sso_is_authenticated() %}
    {{ sso_name() }} - {{ sso_email() }}
    {% if sso_has_role('ROLE_ADMIN') %}...{% endif %}
{% endif %}
```

**Logout Component:**
```twig
<twig:EuripSso:Logout label="Sign Out" class="btn btn-danger" />
```

**Session Management:**
```twig
{% if sso_supports_session_management() %}
    {% include '@EuripSso/components/SessionMonitor.html.twig' %}
{% endif %}
```

**Console Commands:**
```bash
bin/console eurip:sso:cache-warmup
bin/console eurip:sso:test-connection
bin/console eurip:sso:device-login
bin/console eurip:sso:client-credentials
bin/console eurip:sso:introspect <token>
```

### Checklist

- [ ] Update PHP to 8.4+
- [ ] Remove deprecated config options
- [ ] Replace service aliases with FQCN injection
- [ ] Remove `EuripSsoFacade` usage
- [ ] Update event listeners to class-based dispatch
- [ ] Remove `implements OidcConstants` from classes
- [ ] Update direct `OidcClient` usage (if any)
- [ ] Run `composer update`
- [ ] Run `bin/console cache:clear`
- [ ] Test login/logout flow

---

## Upgrading from 0.1.x to 0.2.x

### New Features

- Zero-code integration with `OidcController`
- Automatic user provisioning with `DoctrineOidcUserProvider`
- New events: `OidcPreLoginEvent`, `OidcUserCreatedEvent`, `OidcUserUpdatedEvent`, `OidcPreLogoutEvent`

### Configuration

Add new config sections if needed:

```yaml
eurip_sso:
    controller:
        enabled: true
    routes:
        login: /auth/login
        # ...
    user_provider:
        enabled: true
        entity: App\Entity\User
        # ...
```

### Security Configuration

Update `security.yaml` to use the new authenticator:

```yaml
security:
    providers:
        app_user_provider:
            id: Jostkleigrewe\Sso\Bundle\Security\DoctrineOidcUserProvider

    firewalls:
        main:
            custom_authenticators:
                - Jostkleigrewe\Sso\Bundle\Security\OidcAuthenticator
```
