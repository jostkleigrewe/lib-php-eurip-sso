<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\DTO;

use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;

/**
 * DE: DTO für das OIDC Discovery Document (OpenID Provider Configuration).
 *     Repräsentiert die Antwort von /.well-known/openid-configuration.
 *
 *     HINWEIS: Dieses DTO ist Teil der öffentlichen API und kann direkt
 *     von der Host-Applikation verwendet werden. Nutze `fromArray()` um
 *     JSON-Responses typsicher zu parsen.
 *
 * EN: DTO for the OIDC discovery document (OpenID Provider Configuration).
 *     Represents the response from /.well-known/openid-configuration.
 *
 *     NOTE: This DTO is part of the public API and can be used directly
 *     by the host application. Use `fromArray()` to parse JSON responses
 *     in a type-safe manner.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
final readonly class DiscoveryDocument
{
    public function __construct(
        /**
         * DE: Issuer Identifier (REQUIRED).
         * EN: Issuer identifier (REQUIRED).
         */
        public string $issuer,

        /**
         * DE: Authorization Endpoint URL (REQUIRED).
         * EN: Authorization endpoint URL (REQUIRED).
         */
        public string $authorizationEndpoint,

        /**
         * DE: Token Endpoint URL (REQUIRED für Authorization Code Flow).
         * EN: Token endpoint URL (REQUIRED for authorization code flow).
         */
        public string $tokenEndpoint,

        /**
         * DE: JWKS URI für Signaturvalidierung (REQUIRED wenn Signatur).
         * EN: JWKS URI for signature validation (REQUIRED if signature).
         */
        public ?string $jwksUri = null,

        /**
         * DE: UserInfo Endpoint URL (RECOMMENDED).
         * EN: UserInfo endpoint URL (RECOMMENDED).
         */
        public ?string $userinfoEndpoint = null,

        /**
         * DE: End-Session Endpoint für RP-Initiated Logout (OPTIONAL).
         * EN: End-session endpoint for RP-initiated logout (OPTIONAL).
         */
        public ?string $endSessionEndpoint = null,

        /**
         * DE: Token Revocation Endpoint (RFC 7009, OPTIONAL).
         * EN: Token revocation endpoint (RFC 7009, OPTIONAL).
         */
        public ?string $revocationEndpoint = null,

        /**
         * DE: Token Introspection Endpoint (RFC 7662, OPTIONAL).
         * EN: Token introspection endpoint (RFC 7662, OPTIONAL).
         */
        public ?string $introspectionEndpoint = null,

        /**
         * DE: Device Authorization Endpoint (RFC 8628, OPTIONAL).
         * EN: Device authorization endpoint (RFC 8628, OPTIONAL).
         *
         * @see https://datatracker.ietf.org/doc/html/rfc8628
         */
        public ?string $deviceAuthorizationEndpoint = null,

        /**
         * DE: Unterstützte Response Types (REQUIRED).
         * EN: Supported response types (REQUIRED).
         *
         * @var list<string>
         */
        public array $responseTypesSupported = [],

        /**
         * DE: Unterstützte Grant Types (OPTIONAL, Default: authorization_code, implicit).
         * EN: Supported grant types (OPTIONAL, default: authorization_code, implicit).
         *
         * @var list<string>
         */
        public array $grantTypesSupported = [],

        /**
         * DE: Unterstützte Scopes (RECOMMENDED).
         * EN: Supported scopes (RECOMMENDED).
         *
         * @var list<string>
         */
        public array $scopesSupported = [],

        /**
         * DE: Unterstützte Signaturalgorithmen für ID Token (REQUIRED).
         * EN: Supported signature algorithms for ID token (REQUIRED).
         *
         * @var list<string>
         */
        public array $idTokenSigningAlgValuesSupported = [],

        /**
         * DE: Unterstützte Code Challenge Methods für PKCE (OPTIONAL).
         * EN: Supported code challenge methods for PKCE (OPTIONAL).
         *
         * @var list<string>
         */
        public array $codeChallengeMethodsSupported = [],

        /**
         * DE: Unterstützt Backchannel Logout (OPTIONAL).
         * EN: Supports backchannel logout (OPTIONAL).
         */
        public bool $backchannelLogoutSupported = false,

        /**
         * DE: Unterstützt Frontchannel Logout (OPTIONAL).
         * EN: Supports frontchannel logout (OPTIONAL).
         */
        public bool $frontchannelLogoutSupported = false,

        // ========== Session Management (OpenID Connect Session Management 1.0) ==========

        /**
         * DE: URL zum Check-Session Iframe (OPTIONAL).
         *     Für Session Management via postMessage.
         * EN: URL to check-session iframe (OPTIONAL).
         *     For session management via postMessage.
         *
         * @see https://openid.net/specs/openid-connect-session-1_0.html
         */
        public ?string $checkSessionIframe = null,
    ) {
    }

    /**
     * DE: Erstellt ein DiscoveryDocument aus einem Array (z.B. JSON-Response).
     * EN: Creates a DiscoveryDocument from an array (e.g., JSON response).
     *
     * @param array<string, mixed> $data
     * @throws OidcProtocolException
     */
    public static function fromArray(array $data): self
    {
        // DE: Pflichtfelder prüfen // EN: Validate required fields
        $issuer = $data['issuer'] ?? null;
        if (!is_string($issuer) || $issuer === '') {
            throw new OidcProtocolException('Discovery document missing required field: issuer');
        }

        $authorizationEndpoint = $data['authorization_endpoint'] ?? null;
        if (!is_string($authorizationEndpoint) || $authorizationEndpoint === '') {
            throw new OidcProtocolException('Discovery document missing required field: authorization_endpoint');
        }

        $tokenEndpoint = $data['token_endpoint'] ?? null;
        if (!is_string($tokenEndpoint) || $tokenEndpoint === '') {
            throw new OidcProtocolException('Discovery document missing required field: token_endpoint');
        }

        return new self(
            issuer: $issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $tokenEndpoint,
            jwksUri: self::getStringOrNull($data, 'jwks_uri'),
            userinfoEndpoint: self::getStringOrNull($data, 'userinfo_endpoint'),
            endSessionEndpoint: self::getStringOrNull($data, 'end_session_endpoint'),
            revocationEndpoint: self::getStringOrNull($data, 'revocation_endpoint'),
            introspectionEndpoint: self::getStringOrNull($data, 'introspection_endpoint'),
            deviceAuthorizationEndpoint: self::getStringOrNull($data, 'device_authorization_endpoint'),
            responseTypesSupported: self::getStringArray($data, 'response_types_supported'),
            grantTypesSupported: self::getStringArray($data, 'grant_types_supported'),
            scopesSupported: self::getStringArray($data, 'scopes_supported'),
            idTokenSigningAlgValuesSupported: self::getStringArray($data, 'id_token_signing_alg_values_supported'),
            codeChallengeMethodsSupported: self::getStringArray($data, 'code_challenge_methods_supported'),
            backchannelLogoutSupported: (bool) ($data['backchannel_logout_supported'] ?? false),
            frontchannelLogoutSupported: (bool) ($data['frontchannel_logout_supported'] ?? false),
            checkSessionIframe: self::getStringOrNull($data, 'check_session_iframe'),
        );
    }

    /**
     * DE: Prüft ob PKCE unterstützt wird.
     * EN: Checks if PKCE is supported.
     */
    public function supportsPkce(): bool
    {
        return in_array('S256', $this->codeChallengeMethodsSupported, true)
            || in_array('plain', $this->codeChallengeMethodsSupported, true);
    }

    /**
     * DE: Prüft ob ein bestimmter Grant Type unterstützt wird.
     * EN: Checks if a specific grant type is supported.
     */
    public function supportsGrantType(string $grantType): bool
    {
        // DE: Leeres Array = Default-Werte (authorization_code, implicit)
        // EN: Empty array = default values (authorization_code, implicit)
        if ($this->grantTypesSupported === []) {
            return in_array($grantType, ['authorization_code', 'implicit'], true);
        }

        return in_array($grantType, $this->grantTypesSupported, true);
    }

    /**
     * DE: Prüft ob ein bestimmter Scope unterstützt wird.
     * EN: Checks if a specific scope is supported.
     */
    public function supportsScope(string $scope): bool
    {
        // DE: Leeres Array = keine Info, Scope könnte unterstützt sein
        // EN: Empty array = no info, scope might be supported
        return $this->scopesSupported === [] || in_array($scope, $this->scopesSupported, true);
    }

    /**
     * DE: Prüft ob Session Management unterstützt wird.
     * EN: Checks if session management is supported.
     */
    public function supportsSessionManagement(): bool
    {
        return $this->checkSessionIframe !== null;
    }

    /**
     * DE: Prüft ob Device Authorization Grant (RFC 8628) unterstützt wird.
     * EN: Checks if device authorization grant (RFC 8628) is supported.
     */
    public function supportsDeviceCodeFlow(): bool
    {
        return $this->deviceAuthorizationEndpoint !== null;
    }

    /**
     * DE: Prüft ob Client Credentials Grant (RFC 6749 §4.4) unterstützt wird.
     * EN: Checks if client credentials grant (RFC 6749 §4.4) is supported.
     */
    public function supportsClientCredentials(): bool
    {
        return $this->supportsGrantType('client_credentials');
    }

    /**
     * DE: Prüft ob Token Introspection (RFC 7662) unterstützt wird.
     * EN: Checks if token introspection (RFC 7662) is supported.
     */
    public function supportsIntrospection(): bool
    {
        return $this->introspectionEndpoint !== null;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function getStringOrNull(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param array<string, mixed> $data
     * @return list<string>
     */
    private static function getStringArray(array $data, string $key): array
    {
        $value = $data[$key] ?? [];

        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, 'is_string'));
    }
}
