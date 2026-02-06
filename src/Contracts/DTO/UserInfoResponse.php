<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

use Symfony\Component\Serializer\Attribute\SerializedName;

/**
 * DE: DTO für die Antwort des OIDC UserInfo Endpoints.
 *     Enthält Standard-Claims gemäß OpenID Connect Core 1.0
 *     sowie Custom Claims für EURIP SSO (Rollen, Permissions).
 *
 *     Dieses DTO kann sowohl für Parsing (fromArray) als auch für
 *     Serialisierung (Symfony Serializer) verwendet werden.
 *
 * EN: DTO for the OIDC UserInfo endpoint response.
 *     Contains standard claims according to OpenID Connect Core 1.0
 *     plus custom claims for EURIP SSO (roles, permissions).
 *
 *     This DTO can be used for both parsing (fromArray) and
 *     serialization (Symfony Serializer).
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
 */
final class UserInfoResponse
{
    /**
     * @param list<string>|null $roles
     * @param list<string>|null $clientRoles
     * @param list<string>|null $clientPermissions
     * @param list<string>|null $clientGroups
     */
    public function __construct(
        /**
         * DE: Subject Identifier (stabiler User-Key beim IdP).
         * EN: Subject identifier (stable user key at the IdP).
         */
        public readonly string $sub,

        // ========== email scope ==========

        /**
         * DE: E-Mail (optional, abhängig von Scopes/Claims).
         * EN: Email (optional, depending on scopes/claims).
         */
        public readonly ?string $email = null,

        /**
         * DE: E-Mail verifiziert (optional).
         * EN: Email verified (optional).
         */
        #[SerializedName('email_verified')]
        public readonly ?bool $emailVerified = null,

        // ========== profile scope (OIDC Standard Claims) ==========

        /**
         * DE: Anzeigename (optional).
         * EN: Display name (optional).
         */
        public readonly ?string $name = null,

        /**
         * DE: Vorname (optional, abhängig von Scopes/Claims).
         * EN: Given name (optional, depending on scopes/claims).
         */
        #[SerializedName('given_name')]
        public readonly ?string $givenName = null,

        /**
         * DE: Nachname (optional, abhängig von Scopes/Claims).
         * EN: Family name (optional, depending on scopes/claims).
         */
        #[SerializedName('family_name')]
        public readonly ?string $familyName = null,

        /**
         * DE: Benutzername/Preferred Username (optional).
         * EN: Username/preferred username (optional).
         */
        #[SerializedName('preferred_username')]
        public readonly ?string $preferredUsername = null,

        /**
         * DE: Profilbild URL (optional).
         * EN: Profile picture URL (optional).
         */
        public readonly ?string $picture = null,

        /**
         * DE: Zeitstempel der letzten Profiländerung (optional).
         * EN: Timestamp of last profile update (optional).
         */
        #[SerializedName('updated_at')]
        public readonly ?int $updatedAt = null,

        // ========== profile scope (Custom Claims) ==========

        /**
         * DE: System-Rollen (bei 'profile' Scope).
         * EN: System roles (with 'profile' scope).
         */
        public readonly ?array $roles = null,

        // ========== roles scope (EURIP Custom Claims) ==========

        /**
         * DE: Client-spezifische Rollen (bei 'roles' Scope).
         * EN: Client-specific roles (with 'roles' scope).
         */
        #[SerializedName('client_roles')]
        public readonly ?array $clientRoles = null,

        /**
         * DE: Client-spezifische Permissions (bei 'roles' Scope).
         * EN: Client-specific permissions (with 'roles' scope).
         */
        #[SerializedName('client_permissions')]
        public readonly ?array $clientPermissions = null,

        /**
         * DE: Client-spezifische Gruppen (bei 'roles' Scope).
         * EN: Client-specific groups (with 'roles' scope).
         */
        #[SerializedName('client_groups')]
        public readonly ?array $clientGroups = null,

        /**
         * DE: Ob User für diesen Client blockiert ist (bei 'roles' Scope).
         * EN: Whether user is blocked for this client (with 'roles' scope).
         */
        #[SerializedName('is_blocked')]
        public readonly ?bool $isBlocked = null,
    ) {
    }

    /**
     * DE: Erstellt eine UserInfoResponse aus einem Array (z.B. JSON-Response).
     * EN: Creates a UserInfoResponse from an array (e.g., JSON response).
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            sub: (string) ($data['sub'] ?? ''),
            email: isset($data['email']) ? (string) $data['email'] : null,
            emailVerified: isset($data['email_verified']) ? (bool) $data['email_verified'] : null,
            name: isset($data['name']) ? (string) $data['name'] : null,
            givenName: isset($data['given_name']) ? (string) $data['given_name'] : null,
            familyName: isset($data['family_name']) ? (string) $data['family_name'] : null,
            preferredUsername: isset($data['preferred_username']) ? (string) $data['preferred_username'] : null,
            picture: isset($data['picture']) ? (string) $data['picture'] : null,
            updatedAt: isset($data['updated_at']) ? (int) $data['updated_at'] : null,
            roles: self::getStringArrayOrNull($data, 'roles'),
            clientRoles: self::getStringArrayOrNull($data, 'client_roles'),
            clientPermissions: self::getStringArrayOrNull($data, 'client_permissions'),
            clientGroups: self::getStringArrayOrNull($data, 'client_groups'),
            isBlocked: isset($data['is_blocked']) ? (bool) $data['is_blocked'] : null,
        );
    }

    /**
     * DE: Prüft ob der User für den Client blockiert ist.
     * EN: Checks if the user is blocked for the client.
     */
    public function isBlocked(): bool
    {
        return $this->isBlocked === true;
    }

    /**
     * DE: Prüft ob eine bestimmte Client-Rolle vorhanden ist.
     * EN: Checks if a specific client role is present.
     */
    public function hasClientRole(string $role): bool
    {
        return $this->clientRoles !== null && in_array($role, $this->clientRoles, true);
    }

    /**
     * DE: Prüft ob eine bestimmte Client-Permission vorhanden ist.
     * EN: Checks if a specific client permission is present.
     */
    public function hasClientPermission(string $permission): bool
    {
        return $this->clientPermissions !== null && in_array($permission, $this->clientPermissions, true);
    }

    /**
     * DE: Prüft ob der User in einer bestimmten Client-Gruppe ist.
     * EN: Checks if the user is in a specific client group.
     */
    public function hasClientGroup(string $group): bool
    {
        return $this->clientGroups !== null && in_array($group, $this->clientGroups, true);
    }

    /**
     * @param array<string, mixed> $data
     * @return list<string>|null
     */
    private static function getStringArrayOrNull(array $data, string $key): ?array
    {
        if (!isset($data[$key]) || !is_array($data[$key])) {
            return null;
        }

        return array_values(array_filter($data[$key], 'is_string'));
    }
}
