<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * DE: Interface für OIDC User Provider.
 *     Implementiere dieses Interface in deiner Anwendung.
 *
 * EN: Interface for OIDC user provider.
 *     Implement this interface in your application.
 */
interface OidcUserProviderInterface
{
    /**
     * DE: Lädt oder erstellt einen User basierend auf OIDC Claims.
     * EN: Loads or creates a user based on OIDC claims.
     *
     * @param string $sub Subject identifier from IdP
     * @param TokenResponse $tokenResponse Full token response for additional claims
     */
    public function loadOrCreateUser(string $sub, TokenResponse $tokenResponse): UserInterface;
}
