<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Exception;

/**
 * DE: Fehler bei der Validierung von ID Token Claims.
 * EN: Error during ID token claims validation.
 */
final class ClaimsValidationException extends OidcProtocolException
{
    public function __construct(
        public readonly string $claim,
        public readonly mixed $expected,
        public readonly mixed $actual,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function invalidIssuer(string $expected, string $actual): self
    {
        return new self(
            claim: 'iss',
            expected: $expected,
            actual: $actual,
            message: sprintf('Invalid issuer: expected "%s", got "%s"', $expected, $actual),
        );
    }

    public static function invalidAudience(string $expected, mixed $actual): self
    {
        return new self(
            claim: 'aud',
            expected: $expected,
            actual: $actual,
            message: sprintf('Invalid audience: expected "%s", got "%s"', $expected, is_array($actual) ? implode(', ', $actual) : $actual),
        );
    }

    public static function tokenExpired(int $exp, int $now): self
    {
        return new self(
            claim: 'exp',
            expected: "> $now",
            actual: $exp,
            message: sprintf('Token expired: exp=%d, now=%d', $exp, $now),
        );
    }

    public static function tokenNotYetValid(int $iat, int $now): self
    {
        return new self(
            claim: 'iat',
            expected: "<= $now",
            actual: $iat,
            message: sprintf('Token not yet valid: iat=%d, now=%d', $iat, $now),
        );
    }

    public static function invalidNonce(string $expected, ?string $actual): self
    {
        return new self(
            claim: 'nonce',
            expected: $expected,
            actual: $actual,
            message: sprintf('Invalid nonce: expected "%s", got "%s"', $expected, $actual ?? 'null'),
        );
    }
}
