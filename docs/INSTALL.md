# Installation Guide

Complete setup guide for the EURIP SSO Bundle.

## Requirements

- PHP 8.4+
- Symfony 7.0+ or 8.0+
- PSR-18 HTTP Client (e.g., `symfony/http-client`)
- Doctrine ORM (optional, for user provisioning)

## Step 1: Install Package

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

## Step 2: Register Bundle

```php
// config/bundles.php
return [
    // ...
    Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
];
```

## Step 3: Configure Bundle

Create the configuration file:

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    # Required settings
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'

    # Routes (all have sensible defaults)
    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        after_login: /

    # User provisioning (optional)
    user_provider:
        enabled: true
        entity: App\Entity\User
        mapping:
            subject: oidcSubject
            issuer: oidcIssuer
            email: email
        sync_on_login: true
        auto_create: true
```

## Step 4: Configure Security

```yaml
# config/packages/security.yaml
security:
    providers:
        app_user_provider:
            id: Jostkleigrewe\Sso\Bundle\Security\DoctrineOidcUserProvider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        main:
            lazy: true
            provider: app_user_provider
            custom_authenticators:
                - Jostkleigrewe\Sso\Bundle\Security\OidcAuthenticator
            logout:
                path: eurip_sso_logout
```

## Step 5: Environment Variables

```bash
# .env
SSO_ISSUER_URL=https://sso.example.com
OIDC_CLIENT_ID=your-client-id
APP_URL=https://your-app.com
```

## Step 6: User Entity (Optional)

If using automatic user provisioning, create or modify your User entity:

```php
<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
#[ORM\Table(name: 'users')]
#[ORM\UniqueConstraint(name: 'oidc_identity', columns: ['oidc_issuer', 'oidc_subject'])]
class User implements UserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $oidcSubject = null;

    #[ORM\Column(length: 255)]
    private ?string $oidcIssuer = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $email = null;

    #[ORM\Column(type: 'json')]
    private array $roles = ['ROLE_USER'];

    #[ORM\Column(type: 'json')]
    private array $externalRoles = [];

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getOidcSubject(): ?string
    {
        return $this->oidcSubject;
    }

    public function setOidcSubject(string $oidcSubject): static
    {
        $this->oidcSubject = $oidcSubject;
        return $this;
    }

    public function getOidcIssuer(): ?string
    {
        return $this->oidcIssuer;
    }

    public function setOidcIssuer(string $oidcIssuer): static
    {
        $this->oidcIssuer = $oidcIssuer;
        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): static
    {
        $this->email = $email;
        return $this;
    }

    public function getRoles(): array
    {
        return array_unique(array_merge($this->roles, $this->externalRoles));
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;
        return $this;
    }

    public function getExternalRoles(): array
    {
        return $this->externalRoles;
    }

    public function setExternalRoles(array $externalRoles): static
    {
        $this->externalRoles = $externalRoles;
        return $this;
    }

    public function getUserIdentifier(): string
    {
        return $this->oidcIssuer . '|' . $this->oidcSubject;
    }

    public function eraseCredentials(): void
    {
        // Nothing to erase
    }
}
```

## Step 7: Database Migration

```bash
# Generate migration
bin/console doctrine:migrations:diff

# Run migration
bin/console doctrine:migrations:migrate
```

## Step 8: Cache Warmup (Optional)

Pre-fetch OIDC configuration for faster first login:

```bash
bin/console eurip:sso:cache-warmup
```

## Step 9: Test Connection

Verify your OIDC provider is reachable:

```bash
bin/console eurip:sso:test-connection
```

## Available Routes

After installation, these routes are available:

| Route | Path | Method | Purpose |
|-------|------|--------|---------|
| `eurip_sso_login` | `/auth/login` | GET | Start login |
| `eurip_sso_callback` | `/auth/callback` | GET | SSO callback |
| `eurip_sso_logout` | `/auth/logout` | POST | Logout (CSRF required) |
| `eurip_sso_logout_confirm` | `/auth/logout/confirm` | GET | Logout confirmation |
| `eurip_sso_profile` | `/auth/profile` | GET | User profile |
| `eurip_sso_debug` | `/auth/debug` | GET | OIDC debug info |

## Next Steps

- [Configuration Reference](CONFIGURATION.md) - All configuration options
- [Services](SERVICES.md) - Available services for authorization
- [Events](EVENTS.md) - Customize the authentication flow
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions
