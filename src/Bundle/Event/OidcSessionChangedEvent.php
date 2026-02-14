<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event wenn eine Session-Aenderung erkannt wurde.
 *     Wird vom Frontend (JavaScript) gemeldet und kann server-seitig verarbeitet werden.
 * EN: Event when a session change was detected.
 *     Reported by frontend (JavaScript) and can be processed server-side.
 */
final class OidcSessionChangedEvent extends Event
{
    public function __construct(
        public readonly ?string $previousSessionState = null,
        public readonly ?string $reason = null,
    ) {
    }
}
