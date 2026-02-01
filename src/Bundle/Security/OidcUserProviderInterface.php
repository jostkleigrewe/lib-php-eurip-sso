<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * DE: Interface für OIDC User Provider.
 *     Implementiere dieses Interface um User basierend auf OIDC Claims zu laden/erstellen.
 * EN: Interface for OIDC user provider.
 *     Implement this interface to load/create users based on OIDC claims.
 */
interface OidcUserProviderInterface
{
    /**
     * DE: Lädt oder erstellt einen User basierend auf OIDC Claims.
     * EN: Loads or creates a user based on OIDC claims.
     *
     * @param array<string, mixed> $claims Decoded ID token claims (sub, iss, email, etc.)
     * @param TokenResponse $tokenResponse Full token response (access_token, refresh_token, etc.)
     *
     * @return UserInterface The authenticated user
     */
    public function loadOrCreateUser(array $claims, TokenResponse $tokenResponse): UserInterface;
}
