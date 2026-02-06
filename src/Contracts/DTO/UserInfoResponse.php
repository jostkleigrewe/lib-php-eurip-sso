<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

/**
 * DE: DTO für die Antwort des OIDC UserInfo Endpoints.
 *     Enthält Standard-Claims gemäß OpenID Connect Core 1.0.
 *
 *     HINWEIS: Dieses DTO ist Teil der öffentlichen API und kann direkt
 *     von der Host-Applikation verwendet werden. Nutze `fromArray()` um
 *     JSON-Responses typsicher zu parsen.
 *
 * EN: DTO for the OIDC UserInfo endpoint response.
 *     Contains standard claims according to OpenID Connect Core 1.0.
 *
 *     NOTE: This DTO is part of the public API and can be used directly
 *     by the host application. Use `fromArray()` to parse JSON responses
 *     in a type-safe manner.
 */
final class UserInfoResponse
{
    public function __construct(
        /**
         * DE: Subject Identifier (stabiler User-Key beim IdP).
         * EN: Subject identifier (stable user key at the IdP).
         */
        public readonly string $sub,

        /**
         * DE: E-Mail (optional, abhängig von Scopes/Claims).
         * EN: Email (optional, depending on scopes/claims).
         */
        public readonly ?string $email = null,

        /**
         * DE: Anzeigename (optional).
         * EN: Display name (optional).
         */
        public readonly ?string $name = null,

        /**
         * DE: Vorname (optional, abhängig von Scopes/Claims).
         * EN: Given name (optional, depending on scopes/claims).
         */
        public readonly ?string $givenName = null,

        /**
         * DE: Nachname (optional, abhängig von Scopes/Claims).
         * EN: Family name (optional, depending on scopes/claims).
         */
        public readonly ?string $familyName = null,

        /**
         * DE: Benutzername/Preferred Username (optional).
         * EN: Username/preferred username (optional).
         */
        public readonly ?string $preferredUsername = null,

        /**
         * DE: Profilbild URL (optional).
         * EN: Profile picture URL (optional).
         */
        public readonly ?string $picture = null,

        /**
         * DE: E-Mail verifiziert (optional).
         * EN: Email verified (optional).
         */
        public readonly ?bool $emailVerified = null,
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
            name: isset($data['name']) ? (string) $data['name'] : null,
            givenName: isset($data['given_name']) ? (string) $data['given_name'] : null,
            familyName: isset($data['family_name']) ? (string) $data['family_name'] : null,
            preferredUsername: isset($data['preferred_username']) ? (string) $data['preferred_username'] : null,
            picture: isset($data['picture']) ? (string) $data['picture'] : null,
            emailVerified: isset($data['email_verified']) ? (bool) $data['email_verified'] : null,
        );
    }
}
