# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-02-07

### Added

**Logout Twig Component**
- `<twig:EuripSso:Logout />` - Secure logout with CSRF protection
  - Props: `label`, `class`, `asLink`, `confirm`
  - Renders POST form with hidden CSRF token
  - Can be styled as button or link (`asLink="true"`)

**Logout Confirmation Page (optional)**
- New config: `routes.logout_confirm` (default: `null`)
- GET endpoint for simple logout links
- Shows confirmation page with secure POST button
- Route: `eurip_sso_logout_confirm`

### Fixed

- `profile.html.twig` - Changed broken GET link to `<twig:EuripSso:Logout />` component

### Files Added

```
src/Bundle/Twig/Components/Logout.php
templates/components/Logout.html.twig
templates/logout_confirm.html.twig
```

---

## [0.2.1] - 2026-01-31

### Security

- **verify_signature** now defaults to `true` (was `false`)
  - JWT signature verification is now enabled by default
  - Prevents MITM attacks with forged ID tokens
- **Timing-safe comparisons** for state and nonce validation
  - Uses `hash_equals()` in OidcAuthenticator and OidcSessionStorage
  - Prevents timing attacks on CSRF tokens
- **Open Redirect protection** in login flow
  - Return URL validation rejects `//evil.com`, absolute URLs, newlines
  - Validates URL both when storing and retrieving from session

### Changed

- Migrated to **AbstractBundle** pattern (Symfony 6.1+ best practice)
  - Consolidated `Configuration.php` + `EuripSsoExtension.php` into `EuripSsoBundle.php`
  - Modern directory structure: `config/`, `templates/` at bundle root
- Removed `src/Bundle/DependencyInjection/` directory
- Removed `src/Resources/` directory

---

## [0.2.0] - 2025-01-31

### Added

**Zero-Code Integration**
- `OidcController` - Bundle-provided auth controller
  - `login()` - Redirect to IdP with state/nonce/PKCE
  - `callback()` - Token exchange, user provisioning, session login
  - `logout()` - Session invalidation, SSO logout
  - `profile()` - User profile page (optional)
  - `debug()` - OIDC configuration page (optional)
  - `test()` - Auth workflow test page (optional)
- `OidcRouteLoader` - Dynamic route registration from config
- Configuration: `controller.enabled`, `routes.*`

**Automatic User Provisioning**
- `DoctrineOidcUserProvider` - Creates/updates users from OIDC claims
  - Configurable field mapping (subject, issuer, email, roles)
  - Hybrid strategy: sync external roles, preserve local roles
  - Additional claims sync via `claims_sync` config
  - Implements `UserProviderInterface` for Symfony Security
- `OidcUser` - Generic `UserInterface` implementation
  - Wraps Doctrine entities
  - Merged roles (local + external)
  - User identifier: `issuer|subject`
- Configuration: `user_provider.*`

**Session Management**
- `OidcSessionStorage` - State/nonce/PKCE verifier storage

**New Events**
- `OidcPreLoginEvent` - Before IdP redirect
  - Modify scopes via `setScopes()`
  - Cancel with custom response via `setResponse()`
- `OidcUserCreatedEvent` - After new user creation (before flush)
- `OidcUserUpdatedEvent` - After user update (before flush)
- `OidcPreLogoutEvent` - Before logout
  - Skip SSO logout via `skipSsoLogout()`
  - Cancel with custom response via `setResponse()`

**New Exceptions**
- `ClaimsValidationException` - JWT claims validation errors
- `OidcProtocolException` - OIDC protocol errors

**New DTOs**
- `OidcClientConfig` - Discovery configuration container
- `TokenResponse` - Token exchange response
- `UserInfoResponse` - UserInfo endpoint response

**Templates**
- `@EuripSso/profile.html.twig`
- `@EuripSso/debug.html.twig`
- `@EuripSso/test.html.twig`
- `@EuripSso/layout.html.twig`

### Changed

**OidcLoginSuccessEvent**
- Added `setRoles()`, `addRole()`, `removeRole()` for role modification
- Added `setTargetPath()` for redirect override
- Added `setResponse()` to block login with custom response

**OidcLoginFailureEvent**
- Added `setResponse()` for custom error handling

**Configuration**
- New section: `controller`
- New section: `routes`
- New section: `user_provider`

### Files Added (vs v0.1.0)

```
src/Bundle/Controller/OidcController.php
src/Bundle/Routing/OidcRouteLoader.php
src/Bundle/Security/DoctrineOidcUserProvider.php
src/Bundle/Security/OidcUser.php
src/Bundle/Security/OidcSessionStorage.php
src/Bundle/Event/OidcPreLoginEvent.php
src/Bundle/Event/OidcUserCreatedEvent.php
src/Bundle/Event/OidcUserUpdatedEvent.php
src/Bundle/Event/OidcPreLogoutEvent.php
src/Contracts/Exception/ClaimsValidationException.php
src/Contracts/Exception/OidcProtocolException.php
src/Contracts/DTO/TokenResponse.php
src/Contracts/DTO/UserInfoResponse.php
src/Contracts/Oidc/OidcClientConfig.php
templates/profile.html.twig
templates/debug.html.twig
templates/test.html.twig
templates/layout.html.twig
```

### Files Modified (vs v0.1.0)

```
src/Bundle/DependencyInjection/Configuration.php    # Extended config schema
src/Bundle/DependencyInjection/EuripSsoExtension.php # Service registration
src/Bundle/Event/OidcLoginSuccessEvent.php          # Role/redirect/response
src/Bundle/Event/OidcLoginFailureEvent.php          # Custom response
src/Client/OidcClient.php                           # Extended methods
```

---

## [0.1.0] - 2025-01-31

Initial release.

### Added

**Core Client**
- `OidcClient` - OIDC client implementation
  - `fromDiscovery()` - Auto-discovery from issuer URL
  - `buildAuthorizationUrl()` - Authorization URL with PKCE
  - `exchangeCode()` - Token exchange
  - `refreshToken()` - Token refresh
  - `getUserInfo()` - UserInfo endpoint
  - `decodeIdToken()` - JWT decoding
  - `validateClaims()` - Claims validation
  - `buildLogoutUrl()` - End session URL

**Symfony Bundle**
- `EuripSsoBundle` - Bundle class
- `Configuration` - Bundle configuration
- `EuripSsoExtension` - Service wiring
- `OidcClientFactory` - Client factory service

**Security**
- `OidcAuthenticator` - Symfony Security authenticator
- `OidcUserProviderInterface` - User provider contract

**Events**
- `OidcLoginSuccessEvent` - After successful login
- `OidcLoginFailureEvent` - On login failure
- `OidcTokenRefreshedEvent` - After token refresh

**Exceptions**
- `TokenExchangeFailedException` - Token exchange errors

**Example**
- `ExampleAuthController` - Integration template

### Requirements

- PHP 8.2+
- PSR-18 HTTP Client
- PSR-17 HTTP Factories
- Symfony 7.0+ / 8.x
