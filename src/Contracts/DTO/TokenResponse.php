<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

/**
 * DE: DTO für die Antwort des OAuth2/OIDC Token Endpoints.
 * EN: DTO for the OAuth2/OIDC token endpoint response.
 */
final class TokenResponse
{
    public function __construct(
        public readonly string $accessToken,
        public readonly ?string $idToken,
        public readonly ?string $refreshToken,
        public readonly int $expiresIn,
        public readonly string $tokenType,
    ) {}
}
