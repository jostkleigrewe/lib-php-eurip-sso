<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * DE: Generische OIDC User Implementierung.
 *     Wrapper für Doctrine Entities oder standalone für stateless Auth.
 * EN: Generic OIDC user implementation.
 *     Wrapper for Doctrine entities or standalone for stateless auth.
 */
final class OidcUser implements UserInterface, EquatableInterface, \JsonSerializable
{
    /**
     * @param list<string> $roles
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly int|string $id,
        public readonly string $issuer,
        public readonly string $subject,
        public readonly ?string $email = null,
        public readonly array $roles = ['ROLE_USER'],
        public readonly array $claims = [],
    ) {
    }

    public function getUserIdentifier(): string
    {
        return $this->issuer . '|' . $this->subject;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials(): void
    {
        // No credentials to erase
    }

    public function isEqualTo(UserInterface $user): bool
    {
        if (!$user instanceof self) {
            return false;
        }

        return $this->issuer === $user->issuer
            && $this->subject === $user->subject
            && $this->roles === $user->roles;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'issuer' => $this->issuer,
            'subject' => $this->subject,
            'email' => $this->email,
            'roles' => $this->roles,
        ];
    }

    /**
     * Get a specific claim value.
     */
    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    /**
     * Check if user has a specific role.
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }
}
