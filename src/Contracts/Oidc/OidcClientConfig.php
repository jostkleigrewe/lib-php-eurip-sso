<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Oidc;

/**
 * DE: Konfiguration eines OIDC Clients (aus Sicht des Relying Party/Client).
 *     Diese Daten werden für Authorization-Redirect und Token Exchange benötigt.
 *
 * EN: Configuration of an OIDC client (from the relying party/client perspective).
 *     Required for authorization redirect and token exchange.
 */
final class OidcClientConfig
{
    public function __construct(
        /**
         * DE: Client-ID, wie beim IdP registriert.
         * EN: Client ID as registered with the IdP.
         */
        public readonly string $clientId,

        /**
         * DE: Authorization Endpoint (z.B. /authorize).
         * EN: Authorization endpoint (e.g. /authorize).
         */
        public readonly string $authorizationEndpoint,

        /**
         * DE: Token Endpoint (z.B. /token).
         * EN: Token endpoint (e.g. /token).
         */
        public readonly string $tokenEndpoint,

        /**
         * DE: Redirect URI (Callback) für Authorization Code.
         * EN: Redirect URI (callback) for authorization code.
         */
        public readonly string $redirectUri,

        public readonly string $jwksUri,


        public readonly ?string $issuer = null,
    ) {}
}
