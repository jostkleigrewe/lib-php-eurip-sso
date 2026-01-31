<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event vor OIDC Login-Redirect.
 *     Ermöglicht Abbruch oder Modifikation des Login-Flows.
 * EN: Event before OIDC login redirect.
 *     Allows cancellation or modification of login flow.
 */
final class OidcPreLoginEvent extends Event
{
    public const NAME = OidcConstants::EVENT_PRE_LOGIN;

    private ?Response $response = null;

    /** @var list<string> */
    private array $scopes;

    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public readonly Request $request,
        array $scopes,
    ) {
        $this->scopes = $scopes;
    }

    /**
     * Get the configured scopes for the login request.
     *
     * @return list<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Modify the scopes for the login request.
     *
     * @param list<string> $scopes
     */
    public function setScopes(array $scopes): void
    {
        $this->scopes = $scopes;
    }

    /**
     * Set a custom response to abort the login flow.
     * If set, the controller will return this response instead of redirecting.
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
}
