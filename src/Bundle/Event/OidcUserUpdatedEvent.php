<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event nach Aktualisierung eines bestehenden Users.
 *     Claims wurden synchronisiert.
 * EN: Event after existing user update.
 *     Claims were synchronized.
 */
final class OidcUserUpdatedEvent extends Event
{
    /**
     * @param object $entity The updated entity (not yet flushed)
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly object $entity,
        public readonly array $claims,
        public readonly TokenResponse $tokenResponse,
    ) {
    }
}
