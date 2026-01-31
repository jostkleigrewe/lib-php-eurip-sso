<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event bei fehlgeschlagenem OIDC Login.
 * EN: Event on failed OIDC login.
 */
final class OidcLoginFailureEvent extends Event
{
    public const NAME = 'eurip_sso.login.failure';

    public function __construct(
        public readonly string $error,
        public readonly string $errorDescription,
        public readonly ?\Throwable $exception = null,
    ) {
    }
}
