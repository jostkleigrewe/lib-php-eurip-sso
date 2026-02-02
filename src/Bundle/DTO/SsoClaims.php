<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\DTO;

/**
 * DE: Immutable DTO für OIDC Claims aus dem ID-Token.
 *     Bietet typsicheren Zugriff auf Standard- und Custom-Claims.
 * EN: Immutable DTO for OIDC claims from the ID token.
 *     Provides type-safe access to standard and custom claims.
 */
final readonly class SsoClaims
{
    /**
     * @param array<string, mixed> $claims Raw claims from ID token
     */
    public function __construct(
        private array $claims,
    ) {
    }

    /**
     * DE: Subject Identifier (User-ID beim IdP).
     * EN: Subject identifier (user ID at IdP).
     */
    public function getSubject(): ?string
    {
        return $this->getString('sub');
    }

    /**
     * DE: E-Mail-Adresse.
     * EN: Email address.
     */
    public function getEmail(): ?string
    {
        return $this->getString('email');
    }

    /**
     * DE: Ob E-Mail verifiziert ist.
     * EN: Whether email is verified.
     */
    public function isEmailVerified(): bool
    {
        return $this->getBool('email_verified', false);
    }

    /**
     * DE: Vollständiger Name.
     * EN: Full name.
     */
    public function getName(): ?string
    {
        return $this->getString('name');
    }

    /**
     * DE: Vorname.
     * EN: Given name.
     */
    public function getGivenName(): ?string
    {
        return $this->getString('given_name');
    }

    /**
     * DE: Nachname.
     * EN: Family name.
     */
    public function getFamilyName(): ?string
    {
        return $this->getString('family_name');
    }

    /**
     * DE: Benutzername.
     * EN: Username.
     */
    public function getPreferredUsername(): ?string
    {
        return $this->getString('preferred_username');
    }

    /**
     * DE: Profilbild-URL.
     * EN: Profile picture URL.
     */
    public function getPicture(): ?string
    {
        return $this->getString('picture');
    }

    /**
     * DE: Locale (z.B. "de-DE").
     * EN: Locale (e.g., "de-DE").
     */
    public function getLocale(): ?string
    {
        return $this->getString('locale');
    }

    /**
     * DE: Issuer (IdP URL).
     * EN: Issuer (IdP URL).
     */
    public function getIssuer(): ?string
    {
        return $this->getString('iss');
    }

    /**
     * DE: Audience (Client ID).
     * EN: Audience (client ID).
     */
    public function getAudience(): string|array|null
    {
        $aud = $this->claims['aud'] ?? null;
        if (is_string($aud) || is_array($aud)) {
            return $aud;
        }
        return null;
    }

    /**
     * DE: Token-Ausstellungszeit.
     * EN: Token issued at time.
     */
    public function getIssuedAt(): ?\DateTimeImmutable
    {
        $iat = $this->claims['iat'] ?? null;
        if (!is_int($iat)) {
            return null;
        }
        return (new \DateTimeImmutable())->setTimestamp($iat);
    }

    /**
     * DE: Token-Ablaufzeit.
     * EN: Token expiration time.
     */
    public function getExpiresAt(): ?\DateTimeImmutable
    {
        $exp = $this->claims['exp'] ?? null;
        if (!is_int($exp)) {
            return null;
        }
        return (new \DateTimeImmutable())->setTimestamp($exp);
    }

    // =========================================================================
    // Client-spezifische Claims (EURIP SSO specific)
    // =========================================================================

    /**
     * DE: Globale Rollen des Users (nicht client-spezifisch).
     * EN: Global roles of the user (not client-specific).
     *
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->getStringArray('roles');
    }

    /**
     * DE: Client-spezifische Rollen.
     * EN: Client-specific roles.
     *
     * @return list<string>
     */
    public function getClientRoles(): array
    {
        return $this->getStringArray('client_roles');
    }

    /**
     * DE: Client-spezifische Permissions.
     * EN: Client-specific permissions.
     *
     * @return list<string>
     */
    public function getClientPermissions(): array
    {
        return $this->getStringArray('client_permissions');
    }

    /**
     * DE: Client-spezifische Gruppen.
     * EN: Client-specific groups.
     *
     * @return list<string>
     */
    public function getClientGroups(): array
    {
        return $this->getStringArray('client_groups');
    }

    /**
     * DE: Ob der User für diesen Client blockiert ist.
     * EN: Whether the user is blocked for this client.
     */
    public function isBlocked(): bool
    {
        return $this->getBool('blocked', false);
    }

    // =========================================================================
    // Generic accessors
    // =========================================================================

    /**
     * DE: Gibt einen Claim-Wert zurück.
     * EN: Returns a claim value.
     */
    public function get(string $claim, mixed $default = null): mixed
    {
        return $this->claims[$claim] ?? $default;
    }

    /**
     * DE: Prüft ob ein Claim existiert.
     * EN: Checks if a claim exists.
     */
    public function has(string $claim): bool
    {
        return array_key_exists($claim, $this->claims);
    }

    /**
     * DE: Gibt alle Claims zurück.
     * EN: Returns all claims.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }

    /**
     * DE: Gibt die User-ID zurück (Alias für getSubject).
     * EN: Returns the user ID (alias for getSubject).
     */
    public function getUserId(): ?string
    {
        return $this->getSubject();
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private function getString(string $key): ?string
    {
        $value = $this->claims[$key] ?? null;
        return is_string($value) ? $value : null;
    }

    private function getBool(string $key, bool $default): bool
    {
        $value = $this->claims[$key] ?? null;
        return is_bool($value) ? $value : $default;
    }

    /**
     * @return list<string>
     */
    private function getStringArray(string $key): array
    {
        $value = $this->claims[$key] ?? null;
        if (!is_array($value)) {
            return [];
        }
        return array_values(array_filter($value, 'is_string'));
    }
}
