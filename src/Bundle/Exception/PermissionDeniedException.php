<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Exception;

/**
 * DE: Exception wenn eine Berechtigung nicht vorhanden ist.
 * EN: Exception when a permission is not present.
 */
final class PermissionDeniedException extends \RuntimeException
{
    public function __construct(
        public readonly string $permission,
        public readonly string $type = 'permission',
        string $message = '',
    ) {
        if ($message === '') {
            $message = sprintf('Access denied: missing %s "%s".', $this->type, $this->permission);
        }
        parent::__construct($message);
    }

    public static function forRole(string $role): self
    {
        return new self($role, 'role');
    }

    public static function forPermission(string $permission): self
    {
        return new self($permission, 'permission');
    }

    public static function forGroup(string $group): self
    {
        return new self($group, 'group');
    }

    public static function blocked(): self
    {
        return new self('', 'access', 'Access denied: user is blocked.');
    }
}
