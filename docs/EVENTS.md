# Event System

The EURIP SSO Bundle dispatches events at key points in the authentication flow. Use these events to customize behavior without modifying bundle code.

## Event Dispatch

Events use **class-based dispatch** (Symfony standard since 5.x):

```php
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
class MyListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // Event class determines which event this handles
    }
}
```

---

## Event Overview

| Event | When | Can Modify |
|-------|------|------------|
| `OidcPreLoginEvent` | Before IdP redirect | Scopes, Response |
| `OidcLoginSuccessEvent` | After successful login | Roles, TargetPath, Response |
| `OidcLoginFailureEvent` | On auth error | Response |
| `OidcUserCreatedEvent` | New user created | Entity (before flush) |
| `OidcUserUpdatedEvent` | User synced | Entity (before flush) |
| `OidcPreLogoutEvent` | Before logout | SSO logout skip, Response |
| `OidcTokenRefreshedEvent` | After token refresh | - |
| `OidcBackchannelLogoutEvent` | Back-channel logout | Mark as handled |
| `OidcFrontchannelLogoutEvent` | Front-channel logout | Mark as handled |

---

## Event Flow

### Login Flow

```
User clicks "Login"
        ↓
┌─────────────────┐
│ OidcPreLoginEvent │ → Modify scopes or abort with Response
└────────┬────────┘
         ↓
[Redirect to IdP]
         ↓
[User authenticates]
         ↓
[Callback received]
         ↓
┌─────────────────────┐
│ OidcUserCreatedEvent │ → Only for NEW users (before flush)
│       OR             │
│ OidcUserUpdatedEvent │ → For EXISTING users (before flush)
└────────┬─────────────┘
         ↓
┌──────────────────────┐
│ OidcLoginSuccessEvent │ → Modify roles, redirect, or block
└────────┬─────────────┘
         ↓
[User logged in, redirect to target]
```

### Logout Flow

```
User clicks "Logout"
         ↓
┌──────────────────┐
│ OidcPreLogoutEvent │ → Skip SSO logout or abort
└────────┬─────────┘
         ↓
[Session invalidated]
         ↓
[Redirect to SSO logout or after_logout path]
```

---

## Event Details

### OidcPreLoginEvent

Dispatched before redirecting to the Identity Provider.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcPreLoginEvent;

#[AsEventListener]
class AddScopesListener
{
    public function __invoke(OidcPreLoginEvent $event): void
    {
        // Add custom scopes
        $scopes = $event->getScopes();
        $scopes[] = 'custom:permissions';
        $event->setScopes($scopes);

        // Or abort with custom response
        // $event->setResponse(new Response('...'));
    }
}
```

**Available Methods:**
- `getScopes(): array`
- `setScopes(array $scopes): void`
- `setResponse(Response $response): void` - Abort login

---

### OidcLoginSuccessEvent

Dispatched after successful authentication.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;

#[AsEventListener]
class ModifyRolesListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        // Access claims
        $groups = $event->claims['groups'] ?? [];

        // Add role based on claims
        if (in_array('admins', $groups)) {
            $event->addRole('ROLE_ADMIN');
        }

        // Remove role
        $event->removeRole('ROLE_GUEST');

        // Custom redirect
        if (empty($event->claims['profile_complete'])) {
            $event->setTargetPath('/onboarding');
        }

        // Block login
        if ($event->claims['is_banned'] ?? false) {
            $event->setResponse(new Response('Banned', 403));
        }
    }
}
```

**Available Properties:**
- `claims: array` - All ID token claims

**Available Methods:**
- `getRoles(): array`
- `setRoles(array $roles): void`
- `addRole(string $role): void`
- `removeRole(string $role): void`
- `setTargetPath(string $path): void`
- `setResponse(Response $response): void` - Block login

---

### OidcLoginFailureEvent

Dispatched when authentication fails.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginFailureEvent;

#[AsEventListener]
class CustomErrorPageListener
{
    public function __construct(private Environment $twig) {}

    public function __invoke(OidcLoginFailureEvent $event): void
    {
        $html = $this->twig->render('auth/error.html.twig', [
            'error' => $event->error,
            'description' => $event->errorDescription,
        ]);
        $event->setResponse(new Response($html, 401));
    }
}
```

**Available Properties:**
- `error: string` - Error code
- `errorDescription: ?string` - Error description

**Available Methods:**
- `setResponse(Response $response): void`

---

### OidcUserCreatedEvent

Dispatched when a new user is created (before entity is flushed).

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcUserCreatedEvent;

#[AsEventListener]
class WelcomeEmailListener
{
    public function __construct(private MailerInterface $mailer) {}

    public function __invoke(OidcUserCreatedEvent $event): void
    {
        $email = $event->claims['email'] ?? null;
        if ($email) {
            // Queue welcome email
            // Note: Entity not yet flushed!
            $this->mailer->send(new WelcomeEmail($email));
        }
    }
}
```

**Available Properties:**
- `entity: object` - The new User entity
- `claims: array` - ID token claims

---

### OidcUserUpdatedEvent

Dispatched when an existing user is synced (before entity is flushed).

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcUserUpdatedEvent;

#[AsEventListener]
class LogUserSyncListener
{
    public function __construct(private LoggerInterface $logger) {}

    public function __invoke(OidcUserUpdatedEvent $event): void
    {
        $this->logger->info('User synced', [
            'subject' => $event->claims['sub'] ?? 'unknown',
        ]);
    }
}
```

**Available Properties:**
- `entity: object` - The User entity
- `claims: array` - ID token claims

---

### OidcPreLogoutEvent

Dispatched before logout.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcPreLogoutEvent;

#[AsEventListener]
class LocalLogoutOnlyListener
{
    public function __invoke(OidcPreLogoutEvent $event): void
    {
        // Only invalidate local session
        // Don't redirect to SSO logout
        $event->skipSsoLogout();
    }
}
```

**Available Methods:**
- `skipSsoLogout(): void` - Skip SSO logout redirect
- `setResponse(Response $response): void` - Custom response

---

### OidcTokenRefreshedEvent

Dispatched after token refresh.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcTokenRefreshedEvent;

#[AsEventListener]
class TokenRefreshListener
{
    public function __invoke(OidcTokenRefreshedEvent $event): void
    {
        $tokens = $event->tokenResponse;
        // Log or process new tokens
    }
}
```

**Available Properties:**
- `tokenResponse: TokenResponse` - New tokens

---

### OidcBackchannelLogoutEvent

Dispatched when back-channel logout request is received.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcBackchannelLogoutEvent;

#[AsEventListener]
class BackchannelLogoutListener
{
    public function __invoke(OidcBackchannelLogoutEvent $event): void
    {
        // Invalidate user sessions
        $subject = $event->subject;
        $sessionId = $event->sessionId;

        // Custom session invalidation logic
        $this->sessionManager->invalidateBySubject($subject);

        // Mark as handled
        $event->markHandled();
    }
}
```

**Available Properties:**
- `subject: string` - User subject
- `sessionId: ?string` - SSO session ID
- `claims: array` - Logout token claims

**Available Methods:**
- `markHandled(): void`

---

### OidcFrontchannelLogoutEvent

Dispatched when front-channel logout request is received (via iframe).

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcFrontchannelLogoutEvent;

#[AsEventListener]
class FrontchannelLogoutListener
{
    public function __invoke(OidcFrontchannelLogoutEvent $event): void
    {
        $issuer = $event->issuer;
        $sessionId = $event->sessionId;

        // Handle logout
        $event->markHandled();
    }
}
```

**Available Properties:**
- `issuer: string` - Issuer URL
- `sessionId: ?string` - SSO session ID

**Available Methods:**
- `markHandled(): void`

---

## Common Patterns

### Role Mapping

```php
#[AsEventListener]
class RoleMappingListener
{
    private const GROUP_TO_ROLE = [
        'admins' => 'ROLE_ADMIN',
        'editors' => 'ROLE_EDITOR',
        'moderators' => 'ROLE_MODERATOR',
    ];

    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        $groups = $event->claims['groups'] ?? [];

        foreach (self::GROUP_TO_ROLE as $group => $role) {
            if (in_array($group, $groups, true)) {
                $event->addRole($role);
            }
        }
    }
}
```

### First-Time User Redirect

```php
#[AsEventListener]
class OnboardingListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        $isNewUser = empty($event->claims['last_login']);

        if ($isNewUser) {
            $event->setTargetPath('/welcome');
        }
    }
}
```

### Audit Logging

```php
#[AsEventListener]
class AuditListener
{
    public function __construct(
        private LoggerInterface $auditLogger,
    ) {}

    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        $this->auditLogger->info('User login', [
            'subject' => $event->claims['sub'],
            'email' => $event->claims['email'] ?? null,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        ]);
    }
}
```

---

## See Also

- [Services](SERVICES.md) - Available services
- [Configuration](CONFIGURATION.md) - Event-related configuration
- [Troubleshooting](TROUBLESHOOTING.md) - Common event issues
