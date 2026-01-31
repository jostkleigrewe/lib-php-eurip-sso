<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Oidc;

/**
 * DE: Konfiguration eines OIDC Clients (aus Sicht des Relying Party/Client).
 * EN: Configuration of an OIDC client (from the relying party/client perspective).
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
         * DE: Issuer URL des Identity Providers (für Validierung).
         * EN: Issuer URL of the identity provider (for validation).
         */
        public readonly string $issuer,

        /**
         * DE: Authorization Endpoint (Browser-Redirect, public URL).
         * EN: Authorization endpoint (browser redirect, public URL).
         */
        public readonly string $authorizationEndpoint,

        /**
         * DE: Token Endpoint (Server-to-Server, kann internal URL sein).
         * EN: Token endpoint (server-to-server, can be internal URL).
         */
        public readonly string $tokenEndpoint,

        /**
         * DE: JWKS URI für Signaturvalidierung.
         * EN: JWKS URI for signature validation.
         */
        public readonly string $jwksUri,

        /**
         * DE: Redirect URI (Callback) für Authorization Code.
         * EN: Redirect URI (callback) for authorization code.
         */
        public readonly string $redirectUri,

        /**
         * DE: UserInfo Endpoint.
         * EN: UserInfo endpoint.
         */
        public readonly string $userInfoEndpoint,

        /**
         * DE: End-Session Endpoint für SSO-Logout (optional, public URL).
         * EN: End-session endpoint for SSO logout (optional, public URL).
         */
        public readonly ?string $endSessionEndpoint = null,

        /**
         * DE: Client Secret (optional für public clients).
         * EN: Client secret (optional for public clients).
         */
        public readonly ?string $clientSecret = null,

        /**
         * DE: Public Issuer URL für Browser-Redirects (falls unterschiedlich von issuer).
         *     Wird für Authorization und End-Session Endpoints verwendet.
         * EN: Public issuer URL for browser redirects (if different from issuer).
         *     Used for authorization and end-session endpoints.
         */
        public readonly ?string $publicIssuer = null,
    ) {
    }

    /**
     * DE: Gibt die öffentliche Issuer-URL zurück (für Browser-Redirects).
     * EN: Returns the public issuer URL (for browser redirects).
     */
    public function getPublicIssuer(): string
    {
        return $this->publicIssuer ?? $this->issuer;
    }
}
