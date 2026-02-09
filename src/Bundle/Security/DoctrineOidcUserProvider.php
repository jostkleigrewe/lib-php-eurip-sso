<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Doctrine\ORM\EntityManagerInterface;
use Jostkleigrewe\Sso\Bundle\Event\OidcUserCreatedEvent;
use Jostkleigrewe\Sso\Bundle\Event\OidcUserUpdatedEvent;
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Psr\Log\LoggerInterface;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * DE: Doctrine-basierter OIDC User Provider.
 *     Lädt/erstellt User basierend auf OIDC Claims. Hybrid-Strategie:
 *     SSO-Daten werden bei jedem Login synchronisiert, lokale Daten bleiben erhalten.
 * EN: Doctrine-based OIDC user provider.
 *     Loads/creates users based on OIDC claims. Hybrid strategy:
 *     SSO data is synced on each login, local data is preserved.
 *
 * @implements UserProviderInterface<OidcUser>
 */
final class DoctrineOidcUserProvider implements OidcUserProviderInterface, UserProviderInterface
{
    /**
     * @param class-string $entityClass
     * @param array{subject: string, issuer: string, email: string|null, roles: string|null, external_roles: string|null} $mapping
     * @param array<string, string> $claimsSync
     * @param list<string> $defaultRoles
     */
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly PropertyAccessorInterface $propertyAccessor,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly string $entityClass,
        private readonly array $mapping,
        private readonly array $claimsSync = [],
        private readonly string $rolesClaim = 'roles',
        private readonly array $defaultRoles = ['ROLE_USER'],
        private readonly bool $syncOnLogin = true,
        private readonly bool $autoCreate = true,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function loadOrCreateUser(array $claims, TokenResponse $tokenResponse): UserInterface
    {
        $sub = $claims['sub'] ?? throw new \RuntimeException('Missing sub claim');
        $iss = $claims['iss'] ?? throw new \RuntimeException('Missing iss claim');

        $entity = $this->findByOidcIdentity($iss, $sub);
        $isNewUser = false;

        if ($entity === null) {
            if (!$this->autoCreate) {
                throw new \RuntimeException(sprintf(
                    'User not found for issuer "%s" and subject "%s"',
                    $iss,
                    $sub
                ));
            }

            $entity = $this->createUser($iss, $sub, $claims);
            $isNewUser = true;
            $this->logger?->info('OIDC user created', [
                'issuer' => $iss,
                'subject' => $sub,
            ]);

            // Dispatch user created event (before flush)
            $this->eventDispatcher->dispatch(
                new OidcUserCreatedEvent($entity, $claims, $tokenResponse),
            );
        } elseif ($this->syncOnLogin) {
            $this->syncClaims($entity, $claims);
            $this->logger?->debug('OIDC user synced', [
                'issuer' => $iss,
                'subject' => $sub,
            ]);

            // Dispatch user updated event (before flush)
            $this->eventDispatcher->dispatch(
                new OidcUserUpdatedEvent($entity, $claims, $tokenResponse),
            );
        }

        $this->entityManager->flush();

        return $this->wrapUser($entity, $claims);
    }

    private function findByOidcIdentity(string $issuer, string $subject): ?object
    {
        $repository = $this->entityManager->getRepository($this->entityClass);

        return $repository->findOneBy([
            $this->mapping['issuer'] => $issuer,
            $this->mapping['subject'] => $subject,
        ]);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function createUser(string $issuer, string $subject, array $claims): object
    {
        // Try to instantiate with constructor args, fall back to reflection
        $entity = $this->instantiateEntity($issuer, $subject);

        // DE: OIDC-Identität setzen (falls Constructor sie nicht gesetzt hat)
        // EN: Set OIDC identity (in case constructor didn't set them)
        try {
            $this->propertyAccessor->setValue($entity, $this->mapping['issuer'], $issuer);
            $this->propertyAccessor->setValue($entity, $this->mapping['subject'], $subject);
        } catch (\Throwable $e) {
            // DE: Readonly-Properties nach Constructor sind erwartbar, aber loggen für Debugging
            // EN: Readonly properties after constructor are expected, but log for debugging
            $this->logger?->debug('OIDC user provider: Could not set identity properties (likely readonly)', [
                'entity_class' => $this->entityClass,
                'error' => $e->getMessage(),
            ]);
        }

        // Set default roles
        if ($this->mapping['roles'] !== null) {
            $this->propertyAccessor->setValue($entity, $this->mapping['roles'], $this->defaultRoles);
        }

        // Sync claims
        $this->syncClaims($entity, $claims);

        $this->entityManager->persist($entity);

        return $entity;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function syncClaims(object $entity, array $claims): void
    {
        // Sync email
        if ($this->mapping['email'] !== null && isset($claims['email'])) {
            $currentEmail = $this->propertyAccessor->getValue($entity, $this->mapping['email']);
            if ($currentEmail !== $claims['email']) {
                $this->propertyAccessor->setValue($entity, $this->mapping['email'], $claims['email']);
            }
        }

        // Sync external roles from SSO
        if ($this->mapping['external_roles'] !== null && isset($claims[$this->rolesClaim])) {
            $externalRoles = $this->normalizeRoles($claims[$this->rolesClaim]);
            $currentRoles = $this->propertyAccessor->getValue($entity, $this->mapping['external_roles']) ?? [];
            if ($externalRoles !== $currentRoles) {
                $this->propertyAccessor->setValue($entity, $this->mapping['external_roles'], $externalRoles);
            }
        }

        // Sync additional configured claims
        foreach ($this->claimsSync as $claimName => $propertyName) {
            if (isset($claims[$claimName])) {
                $this->propertyAccessor->setValue($entity, $propertyName, $claims[$claimName]);
            }
        }
    }

    /**
     * DE: Wraps eine Entity immer in OidcUser (konsistente Rückgabe).
     * EN: Always wraps an entity in OidcUser (consistent return type).
     *
     * @param array<string, mixed> $claims
     */
    private function wrapUser(object $entity, array $claims): OidcUser
    {
        return new OidcUser(
            id: $this->getEntityId($entity),
            issuer: $this->propertyAccessor->getValue($entity, $this->mapping['issuer']),
            subject: $this->propertyAccessor->getValue($entity, $this->mapping['subject']),
            email: $this->mapping['email'] !== null
                ? $this->propertyAccessor->getValue($entity, $this->mapping['email'])
                : ($claims['email'] ?? null),
            roles: $this->buildRoles($entity),
            claims: $claims,
        );
    }

    /**
     * DE: Baut die Rolle-Liste aus Entity-Properties (lokal + extern + Fallback).
     * EN: Builds the role list from entity properties (local + external + fallback).
     *
     * @return list<string>
     */
    private function buildRoles(object $entity): array
    {
        $roles = [];

        if ($this->mapping['roles'] !== null) {
            $roles = $this->propertyAccessor->getValue($entity, $this->mapping['roles']) ?? [];
        }

        if ($this->mapping['external_roles'] !== null) {
            $externalRoles = $this->propertyAccessor->getValue($entity, $this->mapping['external_roles']) ?? [];
            $roles = array_unique(array_merge($roles, $externalRoles));
        }

        if (empty($roles)) {
            $roles = $this->defaultRoles;
        }

        return array_values($roles);
    }

    /**
     * Instantiate entity with constructor arguments.
     *
     * Tries common constructor signatures:
     * 1. (issuer, subject)
     * 2. (subject, issuer)
     * 3. No arguments + property access
     */
    private function instantiateEntity(string $issuer, string $subject): object
    {
        $reflection = new \ReflectionClass($this->entityClass);
        $constructor = $reflection->getConstructor();

        // No constructor - just instantiate
        if ($constructor === null || $constructor->getNumberOfRequiredParameters() === 0) {
            return new ($this->entityClass)();
        }

        $params = $constructor->getParameters();
        $args = [];

        foreach ($params as $param) {
            $name = $param->getName();

            // Map parameter names to values
            if (in_array($name, ['issuer', 'oidcIssuer', 'iss'], true)) {
                $args[] = $issuer;
            } elseif (in_array($name, ['subject', 'oidcSubject', 'sub'], true)) {
                $args[] = $subject;
            } elseif ($param->isDefaultValueAvailable()) {
                $args[] = $param->getDefaultValue();
            } else {
                // Can't determine value, try without constructor
                return $reflection->newInstanceWithoutConstructor();
            }
        }

        return new ($this->entityClass)(...$args);
    }

    private function getEntityId(object $entity): int|string
    {
        // DE: Bevorzugt getId() — Standard bei Doctrine Entities
        // EN: Prefer getId() — standard for Doctrine entities
        if (method_exists($entity, 'getId')) {
            return $entity->getId();
        }

        // DE: Fallback über Doctrine Metadata
        // EN: Fallback via Doctrine metadata
        $metadata = $this->entityManager->getClassMetadata($this->entityClass);
        $identifier = $metadata->getIdentifierValues($entity);

        if (count($identifier) === 0) {
            $this->logger?->warning('OIDC user provider: Entity has no identifier value', [
                'entity_class' => $this->entityClass,
            ]);

            return 0;
        }

        if (count($identifier) > 1) {
            $this->logger?->warning('OIDC user provider: Entity uses composite key, using first value', [
                'entity_class' => $this->entityClass,
                'identifier_fields' => array_keys($identifier),
            ]);
        }

        $firstValue = reset($identifier);

        if ($firstValue === null || $firstValue === false || $firstValue === '') {
            $this->logger?->warning('OIDC user provider: Entity identifier is empty', [
                'entity_class' => $this->entityClass,
            ]);

            return 0;
        }

        return $firstValue;
    }

    /**
     * @param mixed $roles
     * @return list<string>
     */
    private function normalizeRoles(mixed $roles): array
    {
        if (!is_array($roles)) {
            return [];
        }

        $roles = array_map('strval', $roles);
        $roles = array_map('trim', $roles);
        $roles = array_filter($roles, static fn (string $r) => $r !== '');
        $roles = array_values(array_unique($roles));
        sort($roles);

        return $roles;
    }

    // ========================================================================
    // UserProviderInterface Implementation
    // ========================================================================

    /**
     * Loads user by identifier (issuer|subject format).
     */
    public function loadUserByIdentifier(string $identifier): OidcUser
    {
        $parts = explode('|', $identifier, 2);
        if (count($parts) !== 2) {
            throw new UserNotFoundException(sprintf('Invalid user identifier format: %s', $identifier));
        }

        [$issuer, $subject] = $parts;
        $entity = $this->findByOidcIdentity($issuer, $subject);

        if ($entity === null) {
            throw new UserNotFoundException(sprintf('User not found: %s', $identifier));
        }

        $claims = [
            'iss' => $issuer,
            'sub' => $subject,
        ];

        return $this->wrapUser($entity, $claims);
    }

    /**
     * Refreshes the user from the database.
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$this->supportsClass($user::class)) {
            throw new \InvalidArgumentException(sprintf(
                'Unsupported user class: %s',
                $user::class
            ));
        }

        if ($user instanceof OidcUser) {
            return $this->loadUserByIdentifier($user->getUserIdentifier());
        }

        // For entity users, reload from database
        $identifier = $user->getUserIdentifier();

        return $this->loadUserByIdentifier($identifier);
    }

    /**
     * Supports OidcUser and the configured entity class.
     */
    public function supportsClass(string $class): bool
    {
        return $class === OidcUser::class
            || is_a($class, $this->entityClass, true);
    }
}
