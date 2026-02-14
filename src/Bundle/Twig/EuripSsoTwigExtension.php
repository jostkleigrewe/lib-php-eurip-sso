<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Twig;

use Jostkleigrewe\Sso\Bundle\Service\EuripSsoAuthorizationService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;
use Jostkleigrewe\Sso\Client\OidcClient;
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
        private readonly EuripSsoClaimsService $claimsService,
        private readonly EuripSsoAuthorizationService $authorizationService,
        private readonly ?EuripSsoTokenStorage $tokenStorage = null,
        private readonly ?OidcClient $oidcClient = null,
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
            // DE: Session Management Funktionen // EN: Session management functions
            new TwigFunction('sso_session_management_config', $this->getSessionManagementConfig(...)),
            new TwigFunction('sso_supports_session_management', $this->supportsSessionManagement(...)),
        ];
    }

    /**
     * DE: Prüft ob ein User authentifiziert ist.
     * EN: Checks if a user is authenticated.
     */
    public function isAuthenticated(): bool
    {
        return $this->claimsService->isAuthenticated();
    }

    /**
     * DE: Gibt die E-Mail-Adresse des eingeloggten Users zurück.
     * EN: Returns the email address of the logged-in user.
     */
    public function getEmail(): ?string
    {
        return $this->claimsService->getEmail();
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
        return $this->claimsService->getUserId();
    }

    /**
     * DE: Prüft ob der User eine Rolle hat (global oder client-spezifisch).
     * EN: Checks if the user has a role (global or client-specific).
     */
    public function hasRole(string $role): bool
    {
        return $this->authorizationService->hasRole($role)
            || $this->authorizationService->hasClientRole($role);
    }

    /**
     * DE: Prüft ob der User eine Permission hat.
     * EN: Checks if the user has a permission.
     */
    public function hasPermission(string $permission): bool
    {
        return $this->authorizationService->hasPermission($permission);
    }

    /**
     * DE: Prüft ob der User in einer Gruppe ist.
     * EN: Checks if the user is in a group.
     */
    public function hasGroup(string $group): bool
    {
        return $this->authorizationService->isInGroup($group);
    }

    /**
     * DE: Gibt einen beliebigen Claim-Wert zurück.
     * EN: Returns any claim value.
     */
    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claimsService->get($name, $default);
    }

    /**
     * DE: Prüft ob OIDC Session Management unterstützt wird.
     * EN: Checks if OIDC session management is supported.
     */
    public function supportsSessionManagement(): bool
    {
        if ($this->oidcClient === null || $this->tokenStorage === null) {
            return false;
        }

        $config = $this->oidcClient->getConfig();

        return $config->checkSessionIframe !== null
            && $this->tokenStorage->getSessionState() !== null;
    }

    /**
     * DE: Gibt die Konfiguration für OIDC Session Management zurück.
     *     Für JavaScript-Integration im Frontend.
     * EN: Returns the configuration for OIDC session management.
     *     For JavaScript integration in the frontend.
     *
     * @return array{
     *     checkSessionIframe: string,
     *     clientId: string,
     *     sessionState: string,
     *     interval: int
     * }|null
     */
    public function getSessionManagementConfig(int $intervalMs = 5000): ?array
    {
        // DE: Frühe Returns wenn nicht unterstützt // EN: Early returns if not supported
        if ($this->oidcClient === null || $this->tokenStorage === null) {
            return null;
        }

        $config = $this->oidcClient->getConfig();
        $sessionState = $this->tokenStorage->getSessionState();

        if ($config->checkSessionIframe === null || $sessionState === null) {
            return null;
        }

        return [
            'checkSessionIframe' => $config->checkSessionIframe,
            'clientId' => $config->clientId,
            'sessionState' => $sessionState,
            'interval' => $intervalMs,
        ];
    }
}
