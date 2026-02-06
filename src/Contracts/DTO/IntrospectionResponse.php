<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

use Symfony\Component\Serializer\Attribute\SerializedName;

/**
 * DE: DTO für den OIDC Token Introspection Endpoint (RFC 7662).
 *     Typsichere Repräsentation der Introspection-Response.
 *
 *     Dieses DTO kann sowohl für Parsing (fromArray) als auch für
 *     Serialisierung (Symfony Serializer) verwendet werden.
 *
 * EN: DTO for OIDC token introspection endpoint (RFC 7662).
 *     Type-safe representation of introspection response.
 *
 *     This DTO can be used for both parsing (fromArray) and
 *     serialization (Symfony Serializer).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
 */
final readonly class IntrospectionResponse
{
    public function __construct(
        /**
         * DE: Ob das Token aktiv/gültig ist (REQUIRED).
         * EN: Whether the token is active/valid (REQUIRED).
         */
        public bool $active,

        /**
         * DE: Scope des Tokens (space-separated).
         * EN: Token scope (space-separated).
         */
        public ?string $scope = null,

        /**
         * DE: Client-ID für die das Token ausgestellt wurde.
         * EN: Client ID the token was issued for.
         */
        #[SerializedName('client_id')]
        public ?string $clientId = null,

        /**
         * DE: Benutzername (human-readable identifier).
         * EN: Username (human-readable identifier).
         */
        public ?string $username = null,

        /**
         * DE: Subject Identifier (User-ID).
         * EN: Subject identifier (user ID).
         */
        public ?string $sub = null,

        /**
         * DE: Token-Typ (z.B. "Bearer").
         * EN: Token type (e.g., "Bearer").
         */
        #[SerializedName('token_type')]
        public ?string $tokenType = null,

        /**
         * DE: Expiration Timestamp (Unix).
         * EN: Expiration timestamp (Unix).
         */
        public ?int $exp = null,

        /**
         * DE: Issued At Timestamp (Unix).
         * EN: Issued at timestamp (Unix).
         */
        public ?int $iat = null,

        /**
         * DE: Not Before Timestamp (Unix).
         * EN: Not before timestamp (Unix).
         */
        public ?int $nbf = null,

        /**
         * DE: Audience (für wen das Token bestimmt ist).
         * EN: Audience (who the token is intended for).
         */
        public ?string $aud = null,

        /**
         * DE: Issuer URI.
         * EN: Issuer URI.
         */
        public ?string $iss = null,

        /**
         * DE: JWT ID (unique identifier).
         * EN: JWT ID (unique identifier).
         */
        public ?string $jti = null,
    ) {
    }

    // ========== Factory Methods ==========

    /**
     * DE: Erstellt eine "inactive" Response (für ungültige Tokens).
     * EN: Creates an "inactive" response (for invalid tokens).
     */
    public static function inactive(): self
    {
        return new self(active: false);
    }

    /**
     * DE: Erstellt Response aus einem Array (z.B. JSON-Response).
     * EN: Creates response from an array (e.g., JSON response).
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            active: (bool) ($data['active'] ?? false),
            scope: isset($data['scope']) ? (string) $data['scope'] : null,
            clientId: isset($data['client_id']) ? (string) $data['client_id'] : null,
            username: isset($data['username']) ? (string) $data['username'] : null,
            sub: isset($data['sub']) ? (string) $data['sub'] : null,
            tokenType: isset($data['token_type']) ? (string) $data['token_type'] : null,
            exp: isset($data['exp']) ? (int) $data['exp'] : null,
            iat: isset($data['iat']) ? (int) $data['iat'] : null,
            nbf: isset($data['nbf']) ? (int) $data['nbf'] : null,
            aud: isset($data['aud']) ? (string) $data['aud'] : null,
            iss: isset($data['iss']) ? (string) $data['iss'] : null,
            jti: isset($data['jti']) ? (string) $data['jti'] : null,
        );
    }

    // ========== Helper Methods ==========

    /**
     * DE: Prüft ob das Token abgelaufen ist.
     * EN: Checks if the token has expired.
     */
    public function isExpired(): bool
    {
        if (!$this->active) {
            return true;
        }

        if ($this->exp === null) {
            return false;
        }

        return $this->exp <= time();
    }

    /**
     * DE: Gibt die verbleibende Gültigkeitsdauer in Sekunden zurück.
     * EN: Returns the remaining validity in seconds.
     */
    public function getRemainingSeconds(): int
    {
        if (!$this->active || $this->exp === null) {
            return 0;
        }

        $remaining = $this->exp - time();

        return max(0, $remaining);
    }

    /**
     * DE: Prüft ob das Token einen bestimmten Scope enthält.
     * EN: Checks if the token contains a specific scope.
     */
    public function hasScope(string $scope): bool
    {
        if ($this->scope === null) {
            return false;
        }

        $scopes = explode(' ', $this->scope);

        return in_array($scope, $scopes, true);
    }

    /**
     * DE: Gibt alle Scopes als Array zurück.
     * EN: Returns all scopes as an array.
     *
     * @return list<string>
     */
    public function getScopes(): array
    {
        if ($this->scope === null || $this->scope === '') {
            return [];
        }

        return explode(' ', $this->scope);
    }
}
