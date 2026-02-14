<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Event;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * DE: Event nach erfolgreichem OIDC Login.
 *     Ermöglicht Modifikation der Rollen oder des Redirect-Ziels.
 * EN: Event after successful OIDC login.
 *     Allows modification of roles or redirect target.
 */
final class OidcLoginSuccessEvent extends Event
{
    /** @var list<string> */
    private array $roles;

    private ?string $targetPath = null;

    private ?Response $response = null;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly UserInterface $user,
        public readonly TokenResponse $tokenResponse,
        public readonly array $claims,
    ) {
        $this->roles = array_values($user->getRoles());
    }

    /**
     * Get the user's roles (possibly modified by listeners).
     *
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * Set/modify the user's roles.
     * These roles will be used for the security token.
     *
     * @param list<string> $roles
     */
    public function setRoles(array $roles): void
    {
        $this->roles = $roles;
    }

    /**
     * Add a role to the user.
     */
    public function addRole(string $role): void
    {
        if (!in_array($role, $this->roles, true)) {
            $this->roles[] = $role;
        }
    }

    /**
     * Remove a role from the user.
     */
    public function removeRole(string $role): void
    {
        $this->roles = array_values(array_filter(
            $this->roles,
            static fn (string $r): bool => $r !== $role
        ));
    }

    /**
     * Get the redirect target path (if overridden).
     */
    public function getTargetPath(): ?string
    {
        return $this->targetPath;
    }

    /**
     * Override the redirect target after login.
     */
    public function setTargetPath(string $targetPath): void
    {
        $this->targetPath = $targetPath;
    }

    /**
     * Set a custom response (e.g. for blocking login).
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
