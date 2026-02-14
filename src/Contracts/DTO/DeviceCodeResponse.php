<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

/**
 * DE: Response vom Device Authorization Endpoint (RFC 8628).
 * EN: Response from Device Authorization Endpoint (RFC 8628).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
 */
final readonly class DeviceCodeResponse
{
    public function __construct(
        /**
         * DE: Der Device Code für Token-Polling.
         * EN: The device code for token polling.
         */
        public string $deviceCode,

        /**
         * DE: Der User Code zur Anzeige für den Benutzer.
         * EN: The user code to display to the user.
         */
        public string $userCode,

        /**
         * DE: Die URL, die der Benutzer im Browser öffnen soll.
         * EN: The URL the user should open in a browser.
         */
        public string $verificationUri,

        /**
         * DE: Ablaufzeit in Sekunden.
         * EN: Expiration time in seconds.
         */
        public int $expiresIn,

        /**
         * DE: Polling-Intervall in Sekunden (Standard: 5).
         * EN: Polling interval in seconds (default: 5).
         */
        public int $interval = 5,

        /**
         * DE: Optionale URL mit vorausgefülltem User Code.
         * EN: Optional URL with pre-filled user code.
         */
        public ?string $verificationUriComplete = null,
    ) {
    }

    /**
     * DE: Erstellt ein DeviceCodeResponse aus einem Array (API-Response).
     * EN: Creates a DeviceCodeResponse from an array (API response).
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            deviceCode: $data['device_code'] ?? throw new \InvalidArgumentException('Missing device_code'),
            userCode: $data['user_code'] ?? throw new \InvalidArgumentException('Missing user_code'),
            verificationUri: $data['verification_uri'] ?? throw new \InvalidArgumentException('Missing verification_uri'),
            expiresIn: (int) ($data['expires_in'] ?? 600),
            interval: (int) ($data['interval'] ?? 5),
            verificationUriComplete: $data['verification_uri_complete'] ?? null,
        );
    }

    /**
     * DE: Berechnet den Ablaufzeitpunkt.
     * EN: Calculates the expiration timestamp.
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return new \DateTimeImmutable(sprintf('+%d seconds', $this->expiresIn));
    }

    /**
     * DE: Prüft ob der Device Code abgelaufen ist.
     * EN: Checks if the device code has expired.
     */
    public function isExpired(): bool
    {
        return $this->getExpiresAt() < new \DateTimeImmutable();
    }

    /**
     * DE: Gibt die beste URL für den Benutzer zurück (mit Code wenn verfügbar).
     * EN: Returns the best URL for the user (with code if available).
     */
    public function getBestVerificationUri(): string
    {
        return $this->verificationUriComplete ?? $this->verificationUri;
    }

    /**
     * DE: Formatiert den User Code für bessere Lesbarkeit (z.B. "ABCD-EFGH").
     * EN: Formats the user code for better readability (e.g., "ABCD-EFGH").
     */
    public function getFormattedUserCode(): string
    {
        // DE: Wenn bereits formatiert, zurückgeben // EN: If already formatted, return as-is
        if (str_contains($this->userCode, '-')) {
            return $this->userCode;
        }

        // DE: 8-stelligen Code in 4-4 Format bringen // EN: Format 8-char code as 4-4
        if (strlen($this->userCode) === 8) {
            return substr($this->userCode, 0, 4) . '-' . substr($this->userCode, 4);
        }

        return $this->userCode;
    }
}
