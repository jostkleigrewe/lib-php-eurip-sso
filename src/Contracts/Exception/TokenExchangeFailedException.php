<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Exception;

/**
 * DE: Fehler beim Token Exchange (z.B. HTTP/Timeout/invalid response).
 * EN: Error during token exchange (e.g. HTTP/timeout/invalid response).
 */
final class TokenExchangeFailedException extends \RuntimeException
{
}
