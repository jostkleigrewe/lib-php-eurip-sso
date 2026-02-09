# Installationsanleitung

Vollständige Setup-Anleitung für das EURIP SSO Bundle.

## Voraussetzungen

- PHP 8.4+
- Symfony 7.0+ oder 8.0+
- PSR-18 HTTP Client (z.B. `symfony/http-client`)
- Doctrine ORM (optional, für User-Provisionierung)

## Schritt 1: Package installieren

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

## Schritt 2: Bundle registrieren

```php
// config/bundles.php
return [
    // ...
    Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
];
```

## Schritt 3: Bundle konfigurieren

Konfigurationsdatei erstellen:

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    # Erforderliche Einstellungen
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'

    # Routen (alle haben sinnvolle Defaults)
    routes:
        login: /auth/login
        callback: /auth/callback
        logout: /auth/logout
        after_login: /

    # User-Provisionierung (optional)
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

## Schritt 4: Security konfigurieren

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

## Schritt 5: Umgebungsvariablen

```bash
# .env
SSO_ISSUER_URL=https://sso.example.com
OIDC_CLIENT_ID=your-client-id
APP_URL=https://your-app.com
```

## Schritt 6: User Entity (Optional)

Bei automatischer User-Provisionierung User Entity erstellen oder anpassen:

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
        // Nichts zu löschen
    }
}
```

## Schritt 7: Datenbank-Migration

```bash
# Migration generieren
bin/console doctrine:migrations:diff

# Migration ausführen
bin/console doctrine:migrations:migrate
```

## Schritt 8: Cache Warmup (Optional)

OIDC-Konfiguration vorladen für schnelleren ersten Login:

```bash
bin/console eurip:sso:cache-warmup
```

## Schritt 9: Verbindung testen

Prüfen ob OIDC Provider erreichbar ist:

```bash
bin/console eurip:sso:test-connection
```

## Verfügbare Routen

Nach der Installation stehen diese Routen zur Verfügung:

| Route | Pfad | Methode | Zweck |
|-------|------|---------|-------|
| `eurip_sso_login` | `/auth/login` | GET | Login starten |
| `eurip_sso_callback` | `/auth/callback` | GET | SSO Callback |
| `eurip_sso_logout` | `/auth/logout` | POST | Logout (CSRF erforderlich) |
| `eurip_sso_logout_confirm` | `/auth/logout/confirm` | GET | Logout-Bestätigung |
| `eurip_sso_profile` | `/auth/profile` | GET | User-Profil |
| `eurip_sso_debug` | `/auth/debug` | GET | OIDC Debug-Info |

## Nächste Schritte

- [Konfigurationsreferenz](CONFIGURATION.md) - Alle Konfigurationsoptionen
- [Services](SERVICES.md) - Verfügbare Services für Autorisierung
- [Events](EVENTS.md) - Authentifizierungs-Flow anpassen
- [Troubleshooting](TROUBLESHOOTING.md) - Häufige Probleme und Lösungen
