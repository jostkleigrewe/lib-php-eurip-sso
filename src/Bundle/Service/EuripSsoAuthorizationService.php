<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

use Jostkleigrewe\Sso\Bundle\Exception\PermissionDeniedException;

/**
 * DE: Service für Berechtigungs-Checks basierend auf OIDC Claims.
 *     Bietet has*-Methoden (return bool) und require*-Methoden (throw Exception).
 * EN: Service for authorization checks based on OIDC claims.
 *     Provides has* methods (return bool) and require* methods (throw exception).
 */
final class EuripSsoAuthorizationService
{
    public function __construct(
        private readonly EuripSsoClaimsService $claimsService,
    ) {
    }

    // =========================================================================
    // Role checks
    // =========================================================================

    /**
     * DE: Prüft ob der User eine globale Rolle hat.
     * EN: Checks if the user has a global role.
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->claimsService->getRoles(), true);
    }

    /**
     * DE: Prüft ob der User eine client-spezifische Rolle hat.
     * EN: Checks if the user has a client-specific role.
     */
    public function hasClientRole(string $role): bool
    {
        return in_array($role, $this->claimsService->getClientRoles(), true);
    }

    /**
     * DE: Prüft ob der User eine beliebige der angegebenen Rollen hat (global oder client).
     * EN: Checks if the user has any of the specified roles (global or client).
     *
     * @param list<string> $roles
     */
    public function hasAnyRole(array $roles): bool
    {
        $userRoles = array_merge(
            $this->claimsService->getRoles(),
            $this->claimsService->getClientRoles()
        );

        foreach ($roles as $role) {
            if (in_array($role, $userRoles, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * DE: Prüft ob der User alle angegebenen Rollen hat (global oder client).
     * EN: Checks if the user has all of the specified roles (global or client).
     *
     * @param list<string> $roles
     */
    public function hasAllRoles(array $roles): bool
    {
        $userRoles = array_merge(
            $this->claimsService->getRoles(),
            $this->claimsService->getClientRoles()
        );

        foreach ($roles as $role) {
            if (!in_array($role, $userRoles, true)) {
                return false;
            }
        }

        return true;
    }

    // =========================================================================
    // Permission checks
    // =========================================================================

    /**
     * DE: Prüft ob der User eine Permission hat.
     * EN: Checks if the user has a permission.
     */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->claimsService->getClientPermissions(), true);
    }

    /**
     * DE: Prüft ob der User eine beliebige der angegebenen Permissions hat.
     * EN: Checks if the user has any of the specified permissions.
     *
     * @param list<string> $permissions
     */
    public function hasAnyPermission(array $permissions): bool
    {
        $userPermissions = $this->claimsService->getClientPermissions();

        foreach ($permissions as $permission) {
            if (in_array($permission, $userPermissions, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * DE: Prüft ob der User alle angegebenen Permissions hat.
     * EN: Checks if the user has all of the specified permissions.
     *
     * @param list<string> $permissions
     */
    public function hasAllPermissions(array $permissions): bool
    {
        $userPermissions = $this->claimsService->getClientPermissions();

        foreach ($permissions as $permission) {
            if (!in_array($permission, $userPermissions, true)) {
                return false;
            }
        }

        return true;
    }

    // =========================================================================
    // Group checks
    // =========================================================================

    /**
     * DE: Prüft ob der User in einer Gruppe ist.
     * EN: Checks if the user is in a group.
     */
    public function isInGroup(string $group): bool
    {
        return in_array($group, $this->claimsService->getClientGroups(), true);
    }

    /**
     * DE: Prüft ob der User in einer beliebigen der angegebenen Gruppen ist.
     * EN: Checks if the user is in any of the specified groups.
     *
     * @param list<string> $groups
     */
    public function isInAnyGroup(array $groups): bool
    {
        $userGroups = $this->claimsService->getClientGroups();

        foreach ($groups as $group) {
            if (in_array($group, $userGroups, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * DE: Prüft ob der User in allen angegebenen Gruppen ist.
     * EN: Checks if the user is in all of the specified groups.
     *
     * @param list<string> $groups
     */
    public function isInAllGroups(array $groups): bool
    {
        $userGroups = $this->claimsService->getClientGroups();

        foreach ($groups as $group) {
            if (!in_array($group, $userGroups, true)) {
                return false;
            }
        }

        return true;
    }

    // =========================================================================
    // Access checks
    // =========================================================================

    /**
     * DE: Prüft ob der User Zugriff hat (nicht blockiert).
     * EN: Checks if the user has access (not blocked).
     */
    public function canAccess(): bool
    {
        if (!$this->claimsService->isAuthenticated()) {
            return false;
        }

        return !$this->claimsService->isBlocked();
    }

    /**
     * DE: Prüft ob der User authentifiziert ist.
     * EN: Checks if the user is authenticated.
     */
    public function isAuthenticated(): bool
    {
        return $this->claimsService->isAuthenticated();
    }

    // =========================================================================
    // Require methods (throw PermissionDeniedException)
    // =========================================================================

    /**
     * DE: Erfordert eine globale oder client-spezifische Rolle.
     * EN: Requires a global or client-specific role.
     *
     * @throws PermissionDeniedException
     */
    public function requireRole(string $role): void
    {
        if (!$this->hasRole($role) && !$this->hasClientRole($role)) {
            throw PermissionDeniedException::forRole($role);
        }
    }

    /**
     * DE: Erfordert eine client-spezifische Rolle.
     * EN: Requires a client-specific role.
     *
     * @throws PermissionDeniedException
     */
    public function requireClientRole(string $role): void
    {
        if (!$this->hasClientRole($role)) {
            throw PermissionDeniedException::forRole($role);
        }
    }

    /**
     * DE: Erfordert eine Permission.
     * EN: Requires a permission.
     *
     * @throws PermissionDeniedException
     */
    public function requirePermission(string $permission): void
    {
        if (!$this->hasPermission($permission)) {
            throw PermissionDeniedException::forPermission($permission);
        }
    }

    /**
     * DE: Erfordert eine beliebige der angegebenen Permissions.
     * EN: Requires any of the specified permissions.
     *
     * @param list<string> $permissions
     * @throws PermissionDeniedException
     */
    public function requireAnyPermission(array $permissions): void
    {
        if (!$this->hasAnyPermission($permissions)) {
            throw PermissionDeniedException::forPermission(implode('|', $permissions));
        }
    }

    /**
     * DE: Erfordert alle angegebenen Permissions.
     * EN: Requires all of the specified permissions.
     *
     * @param list<string> $permissions
     * @throws PermissionDeniedException
     */
    public function requireAllPermissions(array $permissions): void
    {
        $userPermissions = $this->claimsService->getClientPermissions();

        foreach ($permissions as $permission) {
            if (!in_array($permission, $userPermissions, true)) {
                throw PermissionDeniedException::forPermission($permission);
            }
        }
    }

    /**
     * DE: Erfordert Mitgliedschaft in einer Gruppe.
     * EN: Requires membership in a group.
     *
     * @throws PermissionDeniedException
     */
    public function requireGroup(string $group): void
    {
        if (!$this->isInGroup($group)) {
            throw PermissionDeniedException::forGroup($group);
        }
    }

    /**
     * DE: Erfordert Zugriff (nicht blockiert).
     * EN: Requires access (not blocked).
     *
     * @throws PermissionDeniedException
     */
    public function requireAccess(): void
    {
        if (!$this->canAccess()) {
            throw PermissionDeniedException::blocked();
        }
    }

    /**
     * DE: Erfordert Authentifizierung.
     * EN: Requires authentication.
     *
     * @throws PermissionDeniedException
     */
    public function requireAuthentication(): void
    {
        if (!$this->isAuthenticated()) {
            throw new PermissionDeniedException('', 'authentication', 'Authentication required.');
        }
    }
}
