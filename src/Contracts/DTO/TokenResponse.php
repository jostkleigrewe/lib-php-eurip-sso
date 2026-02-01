<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

/**
 * DE: DTO für die Antwort des OAuth2/OIDC Token Endpoints.
 *     Enthält Access Token, ID Token, Refresh Token und Expiration.
 * EN: DTO for the OAuth2/OIDC token endpoint response.
 *     Contains access token, ID token, refresh token and expiration.
 */
final class TokenResponse
{
    public readonly \DateTimeImmutable $expiresAt;
    public readonly \DateTimeImmutable $createdAt;

    public function __construct(
        public readonly string $accessToken,
        public readonly ?string $idToken,
        public readonly ?string $refreshToken,
        public readonly int $expiresIn,
        public readonly string $tokenType,
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
}
