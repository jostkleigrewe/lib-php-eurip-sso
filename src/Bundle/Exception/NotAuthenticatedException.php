<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Exception;

/**
 * DE: Exception wenn ein Service auf Claims zugreift, aber kein User eingeloggt ist.
 * EN: Exception when a service accesses claims but no user is logged in.
 */
final class NotAuthenticatedException extends \RuntimeException
{
    public function __construct(string $message = 'Not authenticated. Please log in first.')
    {
        parent::__construct($message);
    }
}
