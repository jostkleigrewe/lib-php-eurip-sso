<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event bei Back-Channel Logout vom IdP.
 *     Wird ausgelöst wenn der SSO-Server einen Logout-Token sendet.
 *     Apps können dieses Event nutzen um User-Sessions zu invalidieren.
 * EN: Event on back-channel logout from IdP.
 *     Dispatched when SSO server sends a logout token.
 *     Apps can use this event to invalidate user sessions.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
final class OidcBackchannelLogoutEvent extends Event
{
    /**
     * DE: Markiert ob die Session erfolgreich invalidiert wurde.
     * EN: Marks whether the session was successfully invalidated.
     */
    private bool $handled = false;

    /**
     * @param string $subject DE: Der 'sub' Claim aus dem Logout Token / EN: The 'sub' claim from logout token
     * @param string|null $sessionId DE: Die 'sid' aus dem Logout Token (optional) / EN: The 'sid' from logout token (optional)
     * @param string $issuer DE: Der 'iss' Claim aus dem Logout Token / EN: The 'iss' claim from logout token
     * @param array<string, mixed> $claims DE: Alle Claims aus dem Logout Token / EN: All claims from logout token
     */
    public function __construct(
        public readonly string $subject,
        public readonly ?string $sessionId,
        public readonly string $issuer,
        public readonly array $claims,
    ) {
    }

    /**
     * DE: Markiert das Event als behandelt (Session wurde invalidiert).
     * EN: Marks the event as handled (session was invalidated).
     */
    public function markHandled(): void
    {
        $this->handled = true;
    }

    /**
     * DE: Prüft ob das Event behandelt wurde.
     * EN: Checks if the event was handled.
     */
    public function isHandled(): bool
    {
        return $this->handled;
    }
}
