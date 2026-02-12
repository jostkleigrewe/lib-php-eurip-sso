<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Oidc;

/**
 * DE: Konfiguration eines OIDC Clients (aus Sicht des Relying Party/Client).
 * EN: Configuration of an OIDC client (from the relying party/client perspective).
 */
final class OidcClientConfig
{
    /**
     * @throws \InvalidArgumentException
     */
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

        /**
         * DE: Revocation Endpoint für Token-Widerruf (optional, Server-to-Server).
         * EN: Revocation endpoint for token revocation (optional, server-to-server).
         *
         * @see https://datatracker.ietf.org/doc/html/rfc7009
         */
        public readonly ?string $revocationEndpoint = null,

        /**
         * DE: Introspection Endpoint für Token-Validierung (optional, Server-to-Server).
         * EN: Introspection endpoint for token validation (optional, server-to-server).
         *
         * @see https://datatracker.ietf.org/doc/html/rfc7662
         */
        public readonly ?string $introspectionEndpoint = null,

        /**
         * DE: Device Authorization Endpoint für Device Code Flow (optional, Server-to-Server).
         * EN: Device authorization endpoint for device code flow (optional, server-to-server).
         *
         * @see https://datatracker.ietf.org/doc/html/rfc8628
         */
        public readonly ?string $deviceAuthorizationEndpoint = null,
    ) {
        // DE: Pflichtfelder validieren // EN: Validate required fields
        self::validateUrl($issuer, 'issuer');
        self::validateUrl($authorizationEndpoint, 'authorizationEndpoint');
        self::validateUrl($tokenEndpoint, 'tokenEndpoint');
        self::validateUrl($redirectUri, 'redirectUri');

        // DE: Optionale URLs validieren (wenn gesetzt, müssen sie gültig sein)
        // EN: Validate optional URLs (if set, they must be valid)
        if ($jwksUri !== '') {
            self::validateUrl($jwksUri, 'jwksUri');
        }
        if ($userInfoEndpoint !== '') {
            self::validateUrl($userInfoEndpoint, 'userInfoEndpoint');
        }
        if ($publicIssuer !== null) {
            self::validateUrl($publicIssuer, 'publicIssuer');
        }
        if ($endSessionEndpoint !== null) {
            self::validateUrl($endSessionEndpoint, 'endSessionEndpoint');
        }
        if ($revocationEndpoint !== null) {
            self::validateUrl($revocationEndpoint, 'revocationEndpoint');
        }
        if ($introspectionEndpoint !== null) {
            self::validateUrl($introspectionEndpoint, 'introspectionEndpoint');
        }
        if ($deviceAuthorizationEndpoint !== null) {
            self::validateUrl($deviceAuthorizationEndpoint, 'deviceAuthorizationEndpoint');
        }
    }

    /**
     * DE: Validiert eine URL auf korrektes Format.
     * EN: Validates a URL for correct format.
     *
     * @throws \InvalidArgumentException
     */
    private static function validateUrl(string $url, string $fieldName): void
    {
        if ($url === '') {
            throw new \InvalidArgumentException(sprintf('%s cannot be empty', $fieldName));
        }

        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            throw new \InvalidArgumentException(sprintf('%s must be a valid URL: %s', $fieldName, $url));
        }
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
