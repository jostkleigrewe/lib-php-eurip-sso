<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event nach erfolgreichem Token-Refresh.
 * EN: Event after successful token refresh.
 */
final class OidcTokenRefreshedEvent extends Event
{
    public const NAME = 'eurip_sso.token.refreshed';

    public function __construct(
        public readonly TokenResponse $tokenResponse,
        public readonly ?string $previousAccessToken = null,
    ) {
    }
}
