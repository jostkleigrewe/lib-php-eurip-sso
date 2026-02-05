<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Twig;

use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoFacade;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * DE: Twig-Extension für EURIP SSO Integration.
 *     Bietet Funktionen für Authentifizierung und Berechtigungen in Templates.
 * EN: Twig extension for EURIP SSO integration.
 *     Provides functions for authentication and authorization in templates.
 *
 * @example
 * ```twig
 * {% if sso_is_authenticated() %}
 *     Hello {{ sso_name() ?? sso_email() }}!
 *     {% if sso_has_role('ROLE_ADMIN') %}
 *         <a href="/admin">Admin Panel</a>
 *     {% endif %}
 * {% endif %}
 * ```
 */
final class EuripSsoTwigExtension extends AbstractExtension
{
    public function __construct(
        private readonly EuripSsoFacade $facade,
        private readonly EuripSsoClaimsService $claimsService,
    ) {
    }

    /**
     * @return list<TwigFunction>
     */
    public function getFunctions(): array
    {
        return [
            new TwigFunction('sso_is_authenticated', $this->isAuthenticated(...)),
            new TwigFunction('sso_email', $this->getEmail(...)),
            new TwigFunction('sso_name', $this->getName(...)),
            new TwigFunction('sso_user_id', $this->getUserId(...)),
            new TwigFunction('sso_has_role', $this->hasRole(...)),
            new TwigFunction('sso_has_permission', $this->hasPermission(...)),
            new TwigFunction('sso_has_group', $this->hasGroup(...)),
            new TwigFunction('sso_claim', $this->getClaim(...)),
        ];
    }

    /**
     * DE: Prüft ob ein User authentifiziert ist.
     * EN: Checks if a user is authenticated.
     */
    public function isAuthenticated(): bool
    {
        return $this->facade->isAuthenticated();
    }

    /**
     * DE: Gibt die E-Mail-Adresse des eingeloggten Users zurück.
     * EN: Returns the email address of the logged-in user.
     */
    public function getEmail(): ?string
    {
        return $this->facade->getEmail();
    }

    /**
     * DE: Gibt den Namen des eingeloggten Users zurück.
     * EN: Returns the name of the logged-in user.
     */
    public function getName(): ?string
    {
        return $this->claimsService->getName();
    }

    /**
     * DE: Gibt die User-ID (Subject) des eingeloggten Users zurück.
     * EN: Returns the user ID (subject) of the logged-in user.
     */
    public function getUserId(): ?string
    {
        return $this->facade->getUserId();
    }

    /**
     * DE: Prüft ob der User eine Rolle hat (global oder client-spezifisch).
     * EN: Checks if the user has a role (global or client-specific).
     */
    public function hasRole(string $role): bool
    {
        return $this->facade->hasRole($role);
    }

    /**
     * DE: Prüft ob der User eine Permission hat.
     * EN: Checks if the user has a permission.
     */
    public function hasPermission(string $permission): bool
    {
        return $this->facade->hasPermission($permission);
    }

    /**
     * DE: Prüft ob der User in einer Gruppe ist.
     * EN: Checks if the user is in a group.
     */
    public function hasGroup(string $group): bool
    {
        return $this->facade->isInGroup($group);
    }

    /**
     * DE: Gibt einen beliebigen Claim-Wert zurück.
     * EN: Returns any claim value.
     */
    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claimsService->get($name, $default);
    }
}
