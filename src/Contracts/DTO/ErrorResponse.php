<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

use Symfony\Component\Serializer\Attribute\SerializedName;

/**
 * DE: DTO für OAuth2/OIDC Fehler-Responses.
 *     Typsichere Repräsentation gemäß RFC 6749 Section 5.2.
 *
 *     Dieses DTO kann sowohl für Parsing (fromArray) als auch für
 *     Serialisierung (Symfony Serializer) verwendet werden.
 *
 * EN: DTO for OAuth2/OIDC error responses.
 *     Type-safe representation per RFC 6749 Section 5.2.
 *
 *     This DTO can be used for both parsing (fromArray) and
 *     serialization (Symfony Serializer).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
final readonly class ErrorResponse
{
    public function __construct(
        /**
         * DE: Error Code (z.B. "invalid_request", "invalid_token").
         * EN: Error code (e.g., "invalid_request", "invalid_token").
         */
        public string $error,

        /**
         * DE: Optionale menschenlesbare Beschreibung.
         * EN: Optional human-readable description.
         */
        #[SerializedName('error_description')]
        public ?string $errorDescription = null,

        /**
         * DE: Optionale URI zu Fehler-Dokumentation.
         * EN: Optional URI to error documentation.
         */
        #[SerializedName('error_uri')]
        public ?string $errorUri = null,
    ) {
    }

    /**
     * DE: Erstellt eine ErrorResponse aus einem Array (z.B. JSON-Response).
     * EN: Creates an ErrorResponse from an array (e.g., JSON response).
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            error: (string) ($data['error'] ?? 'unknown_error'),
            errorDescription: isset($data['error_description']) ? (string) $data['error_description'] : null,
            errorUri: isset($data['error_uri']) ? (string) $data['error_uri'] : null,
        );
    }

    // ========== Factory Methods ==========

    /**
     * DE: Erstellt einen "invalid_request" Fehler.
     * EN: Creates an "invalid_request" error.
     */
    public static function invalidRequest(?string $description = null): self
    {
        return new self('invalid_request', $description);
    }

    /**
     * DE: Erstellt einen "invalid_token" Fehler.
     * EN: Creates an "invalid_token" error.
     */
    public static function invalidToken(?string $description = null): self
    {
        return new self('invalid_token', $description);
    }

    /**
     * DE: Erstellt einen "invalid_client" Fehler.
     * EN: Creates an "invalid_client" error.
     */
    public static function invalidClient(?string $description = null): self
    {
        return new self('invalid_client', $description);
    }

    /**
     * DE: Erstellt einen "invalid_grant" Fehler.
     * EN: Creates an "invalid_grant" error.
     */
    public static function invalidGrant(?string $description = null): self
    {
        return new self('invalid_grant', $description);
    }

    /**
     * DE: Erstellt einen "access_denied" Fehler.
     * EN: Creates an "access_denied" error.
     */
    public static function accessDenied(?string $description = null): self
    {
        return new self('access_denied', $description);
    }

    /**
     * DE: Erstellt einen "server_error" Fehler.
     * EN: Creates a "server_error" error.
     */
    public static function serverError(?string $description = null): self
    {
        return new self('server_error', $description);
    }

    /**
     * DE: Erstellt einen "temporarily_unavailable" Fehler.
     * EN: Creates a "temporarily_unavailable" error.
     */
    public static function temporarilyUnavailable(?string $description = null): self
    {
        return new self('temporarily_unavailable', $description);
    }

    // ========== Helper Methods ==========

    /**
     * DE: Prüft ob dies ein bestimmter Fehlertyp ist.
     * EN: Checks if this is a specific error type.
     */
    public function isError(string $errorCode): bool
    {
        return $this->error === $errorCode;
    }

    /**
     * DE: Prüft ob der Fehler ein Client-Fehler ist (4xx).
     * EN: Checks if the error is a client error (4xx).
     */
    public function isClientError(): bool
    {
        return in_array($this->error, [
            'invalid_request',
            'invalid_client',
            'invalid_grant',
            'invalid_token',
            'unauthorized_client',
            'unsupported_grant_type',
            'invalid_scope',
            'access_denied',
        ], true);
    }

    /**
     * DE: Prüft ob der Fehler ein Server-Fehler ist (5xx).
     * EN: Checks if the error is a server error (5xx).
     */
    public function isServerError(): bool
    {
        return in_array($this->error, [
            'server_error',
            'temporarily_unavailable',
        ], true);
    }
}
