<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event vor OIDC Logout.
 *     Ermöglicht Abbruch oder Modifikation des Logout-Flows.
 * EN: Event before OIDC logout.
 *     Allows cancellation or modification of logout flow.
 */
final class OidcPreLogoutEvent extends Event
{
    private ?Response $response = null;
    private bool $skipSsoLogout = false;

    public function __construct(
        public readonly Request $request,
        public readonly ?UserInterface $user,
        public readonly ?string $idToken,
    ) {
    }

    /**
     * Set a custom response to abort the normal logout flow.
     */
    public function setResponse(Response $response): void
    {
        $this->response = $response;
        $this->stopPropagation();
    }

    /**
     * Get the custom response if set.
     */
    public function getResponse(): ?Response
    {
        return $this->response;
    }

    /**
     * Check if a custom response was set.
     *
     * @phpstan-assert-if-true !null $this->getResponse()
     */
    public function hasResponse(): bool
    {
        return $this->response !== null;
    }

    /**
     * Skip SSO logout (only invalidate local session).
     */
    public function skipSsoLogout(): void
    {
        $this->skipSsoLogout = true;
    }

    /**
     * Check if SSO logout should be skipped.
     */
    public function shouldSkipSsoLogout(): bool
    {
        return $this->skipSsoLogout;
    }
}
