<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Exception;

use Jostkleigrewe\Sso\Contracts\Oidc\OidcErrorCode;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * DE: Brücke zwischen Domain-Exceptions und Symfony Security.
 *     Wraps OIDC-spezifische Fehler als AuthenticationException für die Authenticator-Pipeline.
 * EN: Bridge between domain exceptions and Symfony Security.
 *     Wraps OIDC-specific errors as AuthenticationException for the authenticator pipeline.
 */
final class OidcAuthenticationException extends AuthenticationException
{
    private function __construct(
        public readonly OidcErrorCode $errorCode,
        string $message,
        public readonly ?\Throwable $originalException = null,
    ) {
        parent::__construct($message, 0, $originalException);
    }

    public static function fromClaimsValidation(ClaimsValidationException $e): self
    {
        return new self(
            errorCode: OidcErrorCode::CLAIMS_INVALID,
            message: sprintf('Claims validation failed: %s', $e->getMessage()),
            originalException: $e,
        );
    }

    public static function fromTokenExchange(TokenExchangeFailedException $e): self
    {
        // DE: Fehlerdetails inkl. error_description für besseres Debugging
        // EN: Error details incl. error_description for better debugging
        $message = $e->errorDescription !== ''
            ? sprintf('Token exchange failed: %s - %s', $e->error, $e->errorDescription)
            : sprintf('Token exchange failed: %s', $e->error);

        return new self(
            errorCode: OidcErrorCode::fromString($e->error),
            message: $message,
            originalException: $e,
        );
    }

    public static function fromProtocol(OidcProtocolException $e): self
    {
        return new self(
            errorCode: OidcErrorCode::PROTOCOL_ERROR,
            message: sprintf('OIDC protocol error: %s', $e->getMessage()),
            originalException: $e,
        );
    }

    public static function fromInternal(\Throwable $e): self
    {
        return new self(
            errorCode: OidcErrorCode::INTERNAL_ERROR,
            message: sprintf('Unexpected authentication error: %s', $e->getMessage()),
            originalException: $e,
        );
    }
}
