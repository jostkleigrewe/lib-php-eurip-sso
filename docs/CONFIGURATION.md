# Configuration Reference

Complete configuration reference for the EURIP SSO Bundle (v0.3.x).

## Minimal Configuration

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'
```

## Full Configuration

```yaml
eurip_sso:
    # ============================================================
    # REQUIRED
    # ============================================================

    # OIDC Issuer URL (internal URL for server-to-server communication)
    issuer: '%env(SSO_ISSUER_URL)%'

    # Client ID registered with the OIDC provider
    client_id: '%env(OIDC_CLIENT_ID)%'

    # Callback URL (must match the registered redirect URI)
    redirect_uri: '%env(APP_URL)%/auth/callback'

    # ============================================================
    # OPTIONAL - Connection Settings
    # ============================================================

    # Client secret (only for confidential clients)
    client_secret: null

    # Public issuer URL for browser redirects (Docker/K8s environments)
    # Use when internal issuer URL differs from public URL
    public_issuer: null

    # Scopes to request
    scopes:
        - openid
        - profile
        - email

    # ============================================================
    # SECURITY
    # ============================================================

    # Require HTTPS for all OIDC endpoints
    # Set to false ONLY for local development with non-HTTPS issuer
    # Default: true
    require_https: true

    # ============================================================
    # CACHE
    # ============================================================

    cache:
        # Enable caching of discovery document and JWKS
        enabled: true

        # Cache TTL in seconds
        ttl: 3600

        # Symfony cache pool to use
        pool: cache.app

    # ============================================================
    # AUTHENTICATOR
    # ============================================================

    authenticator:
        # Register OidcAuthenticator for Symfony Security
        enabled: true

        # Enable JWT signature verification (HIGHLY RECOMMENDED!)
        verify_signature: true

    # ============================================================
    # ROUTES
    # ============================================================

    routes:
        # Core authentication routes
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout

        # Redirect destinations
        after_login: /
        after_logout: /

        # Optional confirmation page (GET, renders button for POST logout)
        logout_confirm: /auth/logout/confirm

        # Optional feature routes (set to null to disable)
        profile: /auth/profile
        debug: /auth/debug
        test: /auth/test

        # OpenID Connect Logout Extensions
        backchannel_logout: null   # POST endpoint for back-channel logout
        frontchannel_logout: null  # GET endpoint for front-channel logout

    # ============================================================
    # USER PROVIDER
    # ============================================================

    user_provider:
        # Enable Doctrine-based user provider
        enabled: false

        # Your User entity class (FQCN)
        entity: null

        # Map OIDC claims to entity properties
        mapping:
            # Required: OIDC identifiers
            subject: oidcSubject
            issuer: oidcIssuer

            # Optional: Additional fields
            email: null
            roles: null
            external_roles: null

        # Sync additional claims to entity properties
        # Format: claim_name: entityProperty
        claims_sync: {}

        # Claim name containing user roles
        roles_claim: roles

        # Default roles for new users
        default_roles:
            - ROLE_USER

        # Update user data on every login
        sync_on_login: true

        # Create new users automatically
        auto_create: true
```

---

## Configuration Options Reference

### Required Options

| Option | Type | Description |
|--------|------|-------------|
| `issuer` | string | OIDC provider URL for server-to-server communication |
| `client_id` | string | Client ID registered with the OIDC provider |
| `redirect_uri` | string | Callback URL (must match registered redirect URI) |

### Connection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `client_secret` | string | `null` | Client secret for confidential clients |
| `public_issuer` | string | `null` | Public URL for browser redirects (Docker/K8s) |
| `scopes` | array | `[openid, profile, email]` | Scopes to request |
| `require_https` | bool | `true` | Enforce HTTPS for all endpoints |

### Cache Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cache.enabled` | bool | `true` | Enable caching |
| `cache.ttl` | int | `3600` | Cache TTL in seconds |
| `cache.pool` | string | `cache.app` | Symfony cache pool |

### Authenticator Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `authenticator.enabled` | bool | `true` | Register OidcAuthenticator |
| `authenticator.verify_signature` | bool | `true` | Verify JWT signatures |

### Route Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `routes.login` | string | `/auth/login` | Login initiation endpoint |
| `routes.callback` | string | `/auth/callback` | OIDC callback endpoint |
| `routes.logout` | string | `/auth/logout` | Logout endpoint (POST only!) |
| `routes.logout_confirm` | string | `/auth/logout/confirm` | Logout confirmation page |
| `routes.after_login` | string | `/` | Redirect after login |
| `routes.after_logout` | string | `/` | Redirect after logout |
| `routes.profile` | string | `/auth/profile` | User profile page |
| `routes.debug` | string | `/auth/debug` | Debug info page |
| `routes.test` | string | `/auth/test` | Auth test page |
| `routes.backchannel_logout` | string | `null` | Back-channel logout endpoint |
| `routes.frontchannel_logout` | string | `null` | Front-channel logout endpoint |

### User Provider Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `user_provider.enabled` | bool | `false` | Enable Doctrine user provider |
| `user_provider.entity` | string | `null` | User entity FQCN |
| `user_provider.mapping.subject` | string | `oidcSubject` | Property for OIDC subject |
| `user_provider.mapping.issuer` | string | `oidcIssuer` | Property for OIDC issuer |
| `user_provider.mapping.email` | string | `null` | Property for email |
| `user_provider.mapping.roles` | string | `null` | Property for local roles |
| `user_provider.mapping.external_roles` | string | `null` | Property for SSO roles |
| `user_provider.claims_sync` | array | `{}` | Additional claim-to-property mapping |
| `user_provider.roles_claim` | string | `roles` | Claim name for roles |
| `user_provider.default_roles` | array | `[ROLE_USER]` | Default roles for new users |
| `user_provider.sync_on_login` | bool | `true` | Sync user data on login |
| `user_provider.auto_create` | bool | `true` | Auto-create new users |

---

## Environment Variables

Recommended environment variables:

```bash
# .env
SSO_ISSUER_URL=https://sso.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret  # Only for confidential clients
APP_URL=https://your-app.com
```

---

## Docker/Kubernetes Setup

For containerized environments where internal and public URLs differ:

```yaml
eurip_sso:
    # Internal URL (server-to-server)
    issuer: 'http://sso-container:8080'

    # Public URL (browser redirects)
    public_issuer: 'https://sso.example.com'

    # For local Docker development, disable HTTPS enforcement
    require_https: false  # NEVER in production!
```

---

## Development Configuration

For local development with non-HTTPS issuer:

```yaml
# config/packages/dev/eurip_sso.yaml
eurip_sso:
    issuer: 'http://localhost:8080'
    require_https: false

    routes:
        debug: /auth/debug
        test: /auth/test
```

---

## Production Checklist

- [ ] `issuer` uses HTTPS
- [ ] `require_https: true` (default)
- [ ] `authenticator.verify_signature: true` (default)
- [ ] `routes.debug` disabled or protected
- [ ] `routes.test` disabled
- [ ] Proper cache pool configured
- [ ] Environment variables secured

---

## See Also

- [Installation Guide](INSTALL.md)
- [Security Features](SECURITY.md)
- [Services](SERVICES.md)
- [Events](EVENTS.md)
