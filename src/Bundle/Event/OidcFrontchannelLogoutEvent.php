<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event bei Front-Channel Logout vom IdP.
 *     Wird ausgelöst wenn der Browser eine Logout-Request via Iframe sendet.
 *     Apps können dieses Event nutzen um User-Sessions zu invalidieren.
 * EN: Event on front-channel logout from IdP.
 *     Dispatched when browser sends logout request via iframe.
 *     Apps can use this event to invalidate user sessions.
 *
 * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html
 */
final class OidcFrontchannelLogoutEvent extends Event
{
    public const NAME = OidcConstants::EVENT_FRONTCHANNEL_LOGOUT;

    /**
     * DE: Markiert ob die Session erfolgreich invalidiert wurde.
     * EN: Marks whether the session was successfully invalidated.
     */
    private bool $handled = false;

    /**
     * @param string $issuer DE: Der 'iss' Parameter aus der Request / EN: The 'iss' parameter from request
     * @param string|null $sessionId DE: Die 'sid' aus der Request (optional) / EN: The 'sid' from request (optional)
     */
    public function __construct(
        public readonly string $issuer,
        public readonly ?string $sessionId,
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
