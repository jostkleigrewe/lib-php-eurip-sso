<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

/**
 * DE: DTO für die Antwort des OIDC UserInfo Endpoints.
 *     Minimal-Set für Login/Provisioning.
 *
 * EN: DTO for the OIDC UserInfo endpoint response.
 *     Minimal set for login/provisioning.
 */
final class UserInfoResponse
{
    public function __construct(
        /**
         * DE: Subject Identifier (stabiler User-Key beim IdP).
         * EN: Subject identifier (stable user key at the IdP).
         */
        public readonly string $sub,

        /**
         * DE: E-Mail (optional, abhängig von Scopes/Claims).
         * EN: Email (optional, depending on scopes/claims).
         */
        public readonly ?string $email = null,

        /**
         * DE: Anzeigename (optional).
         * EN: Display name (optional).
         */
        public readonly ?string $name = null,
    ) {
    }
}
