<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

use Jostkleigrewe\Sso\Bundle\DTO\SsoClaims;
use Jostkleigrewe\Sso\Bundle\Exception\NotAuthenticatedException;
use Jostkleigrewe\Sso\Client\OidcClient;

/**
 * DE: Service für einfachen Zugriff auf OIDC Claims aus dem ID-Token.
 *     Dekodiert das ID-Token und bietet typsicheren Zugriff auf Claims.
 * EN: Service for easy access to OIDC claims from the ID token.
 *     Decodes the ID token and provides type-safe access to claims.
 */
final class EuripSsoClaimsService
{
    private ?SsoClaims $cachedClaims = null;

    public function __construct(
        private readonly EuripSsoTokenStorage $tokenStorage,
        private readonly OidcClient $oidcClient,
    ) {
    }

    // =========================================================================
    // Direct accessors (return null if not authenticated)
    // =========================================================================

    /**
     * DE: Gibt die E-Mail-Adresse zurück.
     * EN: Returns the email address.
     */
    public function getEmail(): ?string
    {
        return $this->getClaimsOrNull()?->getEmail();
    }

    /**
     * DE: Gibt die User-ID (Subject) zurück.
     * EN: Returns the user ID (subject).
     */
    public function getUserId(): ?string
    {
        return $this->getClaimsOrNull()?->getUserId();
    }

    /**
     * DE: Gibt den vollständigen Namen zurück.
     * EN: Returns the full name.
     */
    public function getName(): ?string
    {
        return $this->getClaimsOrNull()?->getName();
    }

    /**
     * DE: Gibt globale Rollen zurück.
     * EN: Returns global roles.
     *
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->getClaimsOrNull()?->getRoles() ?? [];
    }

    /**
     * DE: Gibt client-spezifische Rollen zurück.
     * EN: Returns client-specific roles.
     *
     * @return list<string>
     */
    public function getClientRoles(): array
    {
        return $this->getClaimsOrNull()?->getClientRoles() ?? [];
    }

    /**
     * DE: Gibt client-spezifische Permissions zurück.
     * EN: Returns client-specific permissions.
     *
     * @return list<string>
     */
    public function getClientPermissions(): array
    {
        return $this->getClaimsOrNull()?->getClientPermissions() ?? [];
    }

    /**
     * DE: Gibt client-spezifische Gruppen zurück.
     * EN: Returns client-specific groups.
     *
     * @return list<string>
     */
    public function getClientGroups(): array
    {
        return $this->getClaimsOrNull()?->getClientGroups() ?? [];
    }

    /**
     * DE: Prüft ob der User blockiert ist.
     * EN: Checks if the user is blocked.
     */
    public function isBlocked(): bool
    {
        return $this->getClaimsOrNull()?->isBlocked() ?? false;
    }

    // =========================================================================
    // Generic accessors
    // =========================================================================

    /**
     * DE: Gibt einen beliebigen Claim-Wert zurück.
     * EN: Returns any claim value.
     */
    public function get(string $claim, mixed $default = null): mixed
    {
        return $this->getClaimsOrNull()?->get($claim, $default) ?? $default;
    }

    /**
     * DE: Gibt alle Claims zurück.
     * EN: Returns all claims.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->getClaimsOrNull()?->all() ?? [];
    }

    // =========================================================================
    // Status methods
    // =========================================================================

    /**
     * DE: Prüft ob ein User authentifiziert ist (ID-Token vorhanden).
     * EN: Checks if a user is authenticated (ID token present).
     */
    public function isAuthenticated(): bool
    {
        return $this->tokenStorage->getIdToken() !== null;
    }

    /**
     * DE: Gibt das SsoClaims-Objekt zurück.
     *     Wirft Exception wenn nicht eingeloggt.
     * EN: Returns the SsoClaims object.
     *     Throws exception if not logged in.
     *
     * @throws NotAuthenticatedException
     */
    public function getClaims(): SsoClaims
    {
        $claims = $this->getClaimsOrNull();
        if ($claims === null) {
            throw new NotAuthenticatedException();
        }
        return $claims;
    }

    /**
     * DE: Gibt das SsoClaims-Objekt zurück oder null.
     * EN: Returns the SsoClaims object or null.
     */
    public function getClaimsOrNull(): ?SsoClaims
    {
        // Return cached claims if available
        if ($this->cachedClaims !== null) {
            return $this->cachedClaims;
        }

        $idToken = $this->tokenStorage->getIdToken();
        if ($idToken === null) {
            return null;
        }

        // Decode ID token without signature verification (already verified at login)
        $claims = $this->oidcClient->decodeIdToken(
            idToken: $idToken,
            verifySignature: false,
            validateClaims: false,
        );

        $this->cachedClaims = new SsoClaims($claims);
        return $this->cachedClaims;
    }

    /**
     * DE: Leert den internen Claims-Cache.
     *     Nützlich nach Token-Refresh.
     * EN: Clears the internal claims cache.
     *     Useful after token refresh.
     */
    public function clearCache(): void
    {
        $this->cachedClaims = null;
    }
}
