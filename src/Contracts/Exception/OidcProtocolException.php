<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Exception;

/**
 * DE: Protokoll- oder Validierungsfehler im OAuth2/OIDC Flow.
 *     Basisklasse für spezifische OIDC-Exceptions (ClaimsValidationException, InsecureUrlException).
 * EN: Protocol or validation error in the OAuth2/OIDC flow.
 *     Base class for specific OIDC exceptions (ClaimsValidationException, InsecureUrlException).
 */
class OidcProtocolException extends \RuntimeException
{
}
