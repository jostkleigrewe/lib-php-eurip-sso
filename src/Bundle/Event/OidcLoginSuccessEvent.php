<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event nach erfolgreichem OIDC Login.
 * EN: Event after successful OIDC login.
 */
final class OidcLoginSuccessEvent extends Event
{
    public const NAME = 'eurip_sso.login.success';

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly UserInterface $user,
        public readonly TokenResponse $tokenResponse,
        public readonly array $claims,
    ) {
    }
}
