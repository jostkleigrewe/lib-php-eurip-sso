<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event nach Erstellung eines neuen Users.
 *     Ermöglicht Post-Creation-Logik (z.B. Willkommens-Mail).
 * EN: Event after new user creation.
 *     Allows post-creation logic (e.g. welcome email).
 */
final class OidcUserCreatedEvent extends Event
{
    /**
     * @param object $entity The created entity (not yet flushed)
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly object $entity,
        public readonly array $claims,
        public readonly TokenResponse $tokenResponse,
    ) {
    }
}
