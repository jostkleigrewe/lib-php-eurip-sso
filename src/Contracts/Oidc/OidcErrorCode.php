<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Oidc;

/**
 * DE: OIDC/OAuth 2.0 Fehlercodes.
 *     Enthält Standard-Codes aus RFC 6749 und OpenID Connect Core 1.0,
 *     sowie interne Codes für die Fehlerbehandlung.
 * EN: OIDC/OAuth 2.0 error codes.
 *     Contains standard codes from RFC 6749 and OpenID Connect Core 1.0,
 *     plus internal codes for error handling.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 OAuth 2.0 Authorization Errors
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2 OAuth 2.0 Token Errors
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthError OIDC Authentication Errors
 */
enum OidcErrorCode: string
{
    // =========================================================================
    // OAuth 2.0 Authorization Errors (RFC 6749 §4.1.2.1)
    // =========================================================================

    /**
     * The resource owner or authorization server denied the request.
     */
    case ACCESS_DENIED = 'access_denied';

    /**
     * The request is missing a required parameter, includes an invalid parameter value,
     * includes a parameter more than once, or is otherwise malformed.
     */
    case INVALID_REQUEST = 'invalid_request';

    /**
     * The client is not authorized to request an authorization code using this method.
     */
    case UNAUTHORIZED_CLIENT = 'unauthorized_client';

    /**
     * The authorization server does not support obtaining an authorization code using this method.
     */
    case UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';

    /**
     * The requested scope is invalid, unknown, or malformed.
     */
    case INVALID_SCOPE = 'invalid_scope';

    /**
     * The authorization server encountered an unexpected condition.
     */
    case SERVER_ERROR = 'server_error';

    /**
     * The authorization server is currently unable to handle the request.
     */
    case TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable';

    // =========================================================================
    // OAuth 2.0 Token Errors (RFC 6749 §5.2)
    // =========================================================================

    /**
     * Client authentication failed (e.g., unknown client, no client authentication included,
     * or unsupported authentication method).
     */
    case INVALID_CLIENT = 'invalid_client';

    /**
     * The provided authorization grant or refresh token is invalid, expired, revoked,
     * or was issued to another client.
     */
    case INVALID_GRANT = 'invalid_grant';

    /**
     * The authorization grant type is not supported by the authorization server.
     */
    case UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';

    // =========================================================================
    // OpenID Connect Core 1.0 Errors (§3.1.2.6)
    // =========================================================================

    /**
     * The End-User is REQUIRED to interact with the Authorization Server.
     */
    case INTERACTION_REQUIRED = 'interaction_required';

    /**
     * The Authorization Server requires End-User authentication.
     */
    case LOGIN_REQUIRED = 'login_required';

    /**
     * The Authorization Server requires End-User consent.
     */
    case CONSENT_REQUIRED = 'consent_required';

    /**
     * The OP does not support use of the request parameter.
     */
    case REQUEST_NOT_SUPPORTED = 'request_not_supported';

    /**
     * The OP does not support use of the request_uri parameter.
     */
    case REQUEST_URI_NOT_SUPPORTED = 'request_uri_not_supported';

    /**
     * The OP does not support use of the registration parameter.
     */
    case REGISTRATION_NOT_SUPPORTED = 'registration_not_supported';

    // =========================================================================
    // Internal Errors (Bundle-specific)
    // =========================================================================

    /**
     * Token claims validation failed (wrong issuer, audience, expired, nonce mismatch).
     */
    case CLAIMS_INVALID = 'claims_invalid';

    /**
     * OIDC protocol error (state mismatch, missing parameters, etc.).
     */
    case PROTOCOL_ERROR = 'protocol_error';

    /**
     * Token has expired (used for session/token expiry detection).
     */
    case EXPIRED_TOKEN = 'expired_token';

    /**
     * An unexpected internal error occurred.
     */
    case INTERNAL_ERROR = 'internal_error';

    /**
     * DE: Gibt den Translation-Key für diesen Fehlercode zurück.
     * EN: Returns the translation key for this error code.
     */
    public function getTranslationKey(): string
    {
        return 'eurip_sso.error.' . $this->value;
    }

    /**
     * DE: Prüft, ob dies ein OAuth 2.0 Standard-Fehlercode ist.
     * EN: Checks if this is an OAuth 2.0 standard error code.
     */
    public function isOAuthStandard(): bool
    {
        return in_array($this, [
            self::ACCESS_DENIED,
            self::INVALID_REQUEST,
            self::UNAUTHORIZED_CLIENT,
            self::UNSUPPORTED_RESPONSE_TYPE,
            self::INVALID_SCOPE,
            self::SERVER_ERROR,
            self::TEMPORARILY_UNAVAILABLE,
            self::INVALID_CLIENT,
            self::INVALID_GRANT,
            self::UNSUPPORTED_GRANT_TYPE,
        ], true);
    }

    /**
     * DE: Prüft, ob dies ein OpenID Connect Standard-Fehlercode ist.
     * EN: Checks if this is an OpenID Connect standard error code.
     */
    public function isOidcStandard(): bool
    {
        return in_array($this, [
            self::INTERACTION_REQUIRED,
            self::LOGIN_REQUIRED,
            self::CONSENT_REQUIRED,
            self::REQUEST_NOT_SUPPORTED,
            self::REQUEST_URI_NOT_SUPPORTED,
            self::REGISTRATION_NOT_SUPPORTED,
        ], true);
    }

    /**
     * DE: Prüft, ob dies ein interner (nicht-standard) Fehlercode ist.
     * EN: Checks if this is an internal (non-standard) error code.
     */
    public function isInternal(): bool
    {
        return in_array($this, [
            self::CLAIMS_INVALID,
            self::PROTOCOL_ERROR,
            self::EXPIRED_TOKEN,
            self::INTERNAL_ERROR,
        ], true);
    }

    /**
     * DE: Versucht, einen Fehlercode aus einem String zu erstellen.
     *     Gibt INTERNAL_ERROR zurück, wenn der Code unbekannt ist.
     * EN: Tries to create an error code from a string.
     *     Returns INTERNAL_ERROR if the code is unknown.
     */
    public static function fromString(string $code): self
    {
        return self::tryFrom($code) ?? self::INTERNAL_ERROR;
    }
}
