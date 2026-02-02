<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

/**
 * DE: Facade für bequemen Zugriff auf alle SSO Client-Services.
 *     Alternativ können die Services auch einzeln injiziert werden.
 * EN: Facade for convenient access to all SSO client services.
 *     Alternatively, services can be injected individually.
 *
 * @example
 * ```php
 * public function __construct(private readonly EuripSsoFacade $sso) {}
 *
 * public function index(): Response
 * {
 *     $email = $this->sso->claims()->getEmail();
 *     $isAdmin = $this->sso->auth()->hasRole('ROLE_ADMIN');
 *     $userInfo = $this->sso->api()->getUserInfo();
 * }
 * ```
 */
final class EuripSsoFacade
{
    public function __construct(
        private readonly EuripSsoClaimsService $claimsService,
        private readonly EuripSsoAuthorizationService $authorizationService,
        private readonly EuripSsoApiClient $apiClient,
        private readonly EuripSsoTokenStorage $tokenStorage,
    ) {
    }

    /**
     * DE: Zugriff auf Claims-Service für ID-Token Claims.
     * EN: Access to claims service for ID token claims.
     */
    public function claims(): EuripSsoClaimsService
    {
        return $this->claimsService;
    }

    /**
     * DE: Zugriff auf Authorization-Service für Berechtigungs-Checks.
     * EN: Access to authorization service for permission checks.
     */
    public function auth(): EuripSsoAuthorizationService
    {
        return $this->authorizationService;
    }

    /**
     * DE: Zugriff auf API-Client für SSO Server Calls.
     * EN: Access to API client for SSO server calls.
     */
    public function api(): EuripSsoApiClient
    {
        return $this->apiClient;
    }

    /**
     * DE: Zugriff auf Token-Storage für direkten Token-Zugriff.
     * EN: Access to token storage for direct token access.
     */
    public function tokens(): EuripSsoTokenStorage
    {
        return $this->tokenStorage;
    }

    // =========================================================================
    // Convenience shortcuts
    // =========================================================================

    /**
     * DE: Prüft ob ein User authentifiziert ist.
     * EN: Checks if a user is authenticated.
     */
    public function isAuthenticated(): bool
    {
        return $this->claimsService->isAuthenticated();
    }

    /**
     * DE: Gibt die E-Mail-Adresse zurück.
     * EN: Returns the email address.
     */
    public function getEmail(): ?string
    {
        return $this->claimsService->getEmail();
    }

    /**
     * DE: Gibt die User-ID zurück.
     * EN: Returns the user ID.
     */
    public function getUserId(): ?string
    {
        return $this->claimsService->getUserId();
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
     * DE: Prüft ob der User eine Rolle hat.
     * EN: Checks if the user has a role.
     */
    public function hasRole(string $role): bool
    {
        return $this->authorizationService->hasRole($role)
            || $this->authorizationService->hasClientRole($role);
    }

    /**
     * DE: Prüft ob der User in einer Gruppe ist.
     * EN: Checks if the user is in a group.
     */
    public function isInGroup(string $group): bool
    {
        return $this->authorizationService->isInGroup($group);
    }

    /**
     * DE: Prüft ob der User Zugriff hat (nicht blockiert).
     * EN: Checks if the user has access (not blocked).
     */
    public function canAccess(): bool
    {
        return $this->authorizationService->canAccess();
    }
}
