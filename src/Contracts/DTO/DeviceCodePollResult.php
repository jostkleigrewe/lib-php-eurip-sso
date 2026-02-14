<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

/**
 * DE: Ergebnis eines Device Code Polling-Versuchs (RFC 8628).
 * EN: Result of a device code polling attempt (RFC 8628).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
 */
final readonly class DeviceCodePollResult
{
    /**
     * DE: Status-Konstanten für Polling-Ergebnis.
     * EN: Status constants for polling result.
     */
    public const string STATUS_PENDING = 'authorization_pending';
    public const string STATUS_SLOW_DOWN = 'slow_down';
    public const string STATUS_SUCCESS = 'success';
    public const string STATUS_ACCESS_DENIED = 'access_denied';
    public const string STATUS_EXPIRED = 'expired_token';
    public const string STATUS_INVALID_GRANT = 'invalid_grant';

    public function __construct(
        /**
         * DE: Status des Polling-Versuchs.
         * EN: Status of the polling attempt.
         */
        public string $status,

        /**
         * DE: Token-Response bei Erfolg (null bei Pending/Error).
         * EN: Token response on success (null on pending/error).
         */
        public ?TokenResponse $tokenResponse = null,

        /**
         * DE: Neues Polling-Intervall bei slow_down (null sonst).
         * EN: New polling interval on slow_down (null otherwise).
         */
        public ?int $newInterval = null,

        /**
         * DE: Fehlerbeschreibung bei Error-Status.
         * EN: Error description on error status.
         */
        public ?string $errorDescription = null,
    ) {
    }

    /**
     * DE: Erstellt ein erfolgreiches Ergebnis mit Token.
     * EN: Creates a successful result with token.
     */
    public static function success(TokenResponse $tokenResponse): self
    {
        return new self(
            status: self::STATUS_SUCCESS,
            tokenResponse: $tokenResponse,
        );
    }

    /**
     * DE: Erstellt ein "noch ausstehend" Ergebnis.
     * EN: Creates an "authorization pending" result.
     */
    public static function pending(): self
    {
        return new self(status: self::STATUS_PENDING);
    }

    /**
     * DE: Erstellt ein "langsamer" Ergebnis mit neuem Intervall.
     * EN: Creates a "slow down" result with new interval.
     */
    public static function slowDown(int $currentInterval): self
    {
        return new self(
            status: self::STATUS_SLOW_DOWN,
            newInterval: $currentInterval + 5,
        );
    }

    /**
     * DE: Erstellt ein "Zugriff verweigert" Ergebnis.
     * EN: Creates an "access denied" result.
     */
    public static function accessDenied(?string $description = null): self
    {
        return new self(
            status: self::STATUS_ACCESS_DENIED,
            errorDescription: $description ?? 'The user denied the authorization request.',
        );
    }

    /**
     * DE: Erstellt ein "abgelaufen" Ergebnis.
     * EN: Creates an "expired" result.
     */
    public static function expired(?string $description = null): self
    {
        return new self(
            status: self::STATUS_EXPIRED,
            errorDescription: $description ?? 'The device code has expired.',
        );
    }

    /**
     * DE: Erstellt ein allgemeines Fehler-Ergebnis.
     * EN: Creates a general error result.
     */
    public static function error(string $errorCode, ?string $description = null): self
    {
        return new self(
            status: $errorCode,
            errorDescription: $description,
        );
    }

    /**
     * DE: Prüft ob Polling erfolgreich war.
     * EN: Checks if polling was successful.
     */
    public function isSuccess(): bool
    {
        return $this->status === self::STATUS_SUCCESS;
    }

    /**
     * DE: Prüft ob weiter gepollt werden soll.
     * EN: Checks if polling should continue.
     */
    public function shouldContinuePolling(): bool
    {
        return $this->status === self::STATUS_PENDING || $this->status === self::STATUS_SLOW_DOWN;
    }

    /**
     * DE: Prüft ob ein Fehler aufgetreten ist (nicht fortsetzbar).
     * EN: Checks if an error occurred (not recoverable).
     */
    public function isError(): bool
    {
        return !in_array($this->status, [
            self::STATUS_SUCCESS,
            self::STATUS_PENDING,
            self::STATUS_SLOW_DOWN,
        ], true);
    }

    /**
     * DE: Prüft ob das Intervall erhöht werden soll.
     * EN: Checks if interval should be increased.
     */
    public function shouldSlowDown(): bool
    {
        return $this->status === self::STATUS_SLOW_DOWN;
    }

    /**
     * DE: Gibt das empfohlene Intervall für den nächsten Poll zurück.
     * EN: Returns the recommended interval for the next poll.
     */
    public function getRecommendedInterval(int $currentInterval): int
    {
        if ($this->newInterval !== null) {
            return $this->newInterval;
        }

        return $currentInterval;
    }
}
