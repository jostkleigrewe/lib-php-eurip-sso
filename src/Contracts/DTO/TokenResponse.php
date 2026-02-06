<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

use Symfony\Component\Serializer\Attribute\Ignore;
use Symfony\Component\Serializer\Attribute\SerializedName;

/**
 * DE: DTO für die Antwort des OAuth2/OIDC Token Endpoints.
 *     Enthält Access Token, ID Token, Refresh Token und Expiration.
 *
 *     Dieses DTO kann sowohl für Parsing (fromArray) als auch für
 *     Serialisierung (Symfony Serializer) verwendet werden.
 *
 * EN: DTO for the OAuth2/OIDC token endpoint response.
 *     Contains access token, ID token, refresh token and expiration.
 *
 *     This DTO can be used for both parsing (fromArray) and
 *     serialization (Symfony Serializer).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
final class TokenResponse
{
    /**
     * DE: Berechneter Ablaufzeitpunkt (nicht serialisiert).
     * EN: Calculated expiration time (not serialized).
     */
    #[Ignore]
    public readonly \DateTimeImmutable $expiresAt;

    /**
     * DE: Erstellungszeitpunkt (nicht serialisiert).
     * EN: Creation time (not serialized).
     */
    #[Ignore]
    public readonly \DateTimeImmutable $createdAt;

    public function __construct(
        #[SerializedName('access_token')]
        public readonly string $accessToken,
        #[SerializedName('token_type')]
        public readonly string $tokenType = 'Bearer',
        #[SerializedName('expires_in')]
        public readonly int $expiresIn = 3600,
        #[SerializedName('refresh_token')]
        public readonly ?string $refreshToken = null,
        #[SerializedName('id_token')]
        public readonly ?string $idToken = null,

        /**
         * DE: Scope (space-separated, optional in Response).
         * EN: Scope (space-separated, optional in response).
         */
        public readonly ?string $scope = null,
        ?\DateTimeImmutable $createdAt = null,
    ) {
        $this->createdAt = $createdAt ?? new \DateTimeImmutable();
        $this->expiresAt = $this->createdAt->modify("+{$this->expiresIn} seconds");
    }

    /**
     * DE: Prüft ob das Access Token abgelaufen ist.
     * EN: Checks if the access token has expired.
     */
    public function isExpired(): bool
    {
        return $this->expiresAt <= new \DateTimeImmutable();
    }

    /**
     * DE: Prüft ob das Token bald abläuft (innerhalb des Buffers).
     * EN: Checks if the token will expire soon (within buffer).
     */
    public function isExpiringSoon(int $bufferSeconds = 60): bool
    {
        $bufferTime = (new \DateTimeImmutable())->modify("+{$bufferSeconds} seconds");
        return $this->expiresAt <= $bufferTime;
    }

    /**
     * DE: Gibt die verbleibende Gültigkeitsdauer in Sekunden zurück.
     * EN: Returns the remaining validity in seconds.
     */
    public function getRemainingSeconds(): int
    {
        $now = new \DateTimeImmutable();
        if ($this->expiresAt <= $now) {
            return 0;
        }
        return $this->expiresAt->getTimestamp() - $now->getTimestamp();
    }

    /**
     * DE: Prüft ob ein Refresh Token verfügbar ist.
     * EN: Checks if a refresh token is available.
     */
    public function canRefresh(): bool
    {
        return $this->refreshToken !== null;
    }

    /**
     * DE: Erstellt eine TokenResponse aus einem Array (z.B. JSON-Response).
     * EN: Creates a TokenResponse from an array (e.g., JSON response).
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            accessToken: (string) ($data['access_token'] ?? ''),
            tokenType: (string) ($data['token_type'] ?? 'Bearer'),
            expiresIn: (int) ($data['expires_in'] ?? 3600),
            refreshToken: isset($data['refresh_token']) ? (string) $data['refresh_token'] : null,
            idToken: isset($data['id_token']) ? (string) $data['id_token'] : null,
            scope: isset($data['scope']) ? (string) $data['scope'] : null,
        );
    }
}
