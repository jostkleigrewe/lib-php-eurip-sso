<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event bei fehlgeschlagenem OIDC Login.
 *     Ermöglicht Custom Error Handling und Response.
 * EN: Event on failed OIDC login.
 *     Allows custom error handling and response.
 */
final class OidcLoginFailureEvent extends Event
{
    private ?Response $response = null;

    public function __construct(
        public readonly string $error,
        public readonly string $errorDescription,
        public readonly ?\Throwable $exception = null,
    ) {
    }

    /**
     * Set a custom response to handle the error.
     * If set, the controller will return this response.
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
