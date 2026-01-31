<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * DE: Symfony Bundle für EURIP SSO Integration.
 * EN: Symfony bundle for EURIP SSO integration.
 */
final class EuripSsoBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__, 2);
    }
}
