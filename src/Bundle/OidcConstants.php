<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle;

/**
 * DE: Konstanten für das OIDC SSO Bundle.
 * EN: Constants for the OIDC SSO bundle.
 */
final class OidcConstants
{
    private function __construct()
    {
    }

    // Session Keys
    public const string SESSION_STATE = '_eurip_sso_state';
    public const string SESSION_NONCE = '_eurip_sso_nonce';
    public const string SESSION_VERIFIER = '_eurip_sso_verifier';
    public const string SESSION_ID_TOKEN = '_eurip_sso_id_token';
    public const string SESSION_RETURN_URL = '_eurip_sso_return_url';
    public const string SESSION_ACCESS_TOKEN = '_eurip_sso_access_token';
    public const string SESSION_REFRESH_TOKEN = '_eurip_sso_refresh_token';
    public const string SESSION_TOKEN_EXPIRES = '_eurip_sso_token_expires';
    public const string SESSION_AUTH_ERROR = '_eurip_sso_auth_error';

    // Error TTL (5 minutes)
    public const int AUTH_ERROR_TTL = 300;

    // Route Names
    public const string ROUTE_LOGIN = 'eurip_sso_login';
    public const string ROUTE_CALLBACK = 'eurip_sso_callback';
    public const string ROUTE_LOGOUT = 'eurip_sso_logout';
    public const string ROUTE_LOGOUT_CONFIRM = 'eurip_sso_logout_confirm';
    public const string ROUTE_ERROR = 'eurip_sso_error';
    public const string ROUTE_BACKCHANNEL_LOGOUT = 'eurip_sso_backchannel_logout';
    public const string ROUTE_FRONTCHANNEL_LOGOUT = 'eurip_sso_frontchannel_logout';
    public const string ROUTE_PROFILE = 'eurip_sso_profile';
    public const string ROUTE_DEBUG = 'eurip_sso_debug';
    public const string ROUTE_TEST = 'eurip_sso_test';

    /** @var list<string> */
    public const array DEFAULT_SCOPES = ['openid', 'profile', 'email'];

    public const string DEFAULT_FIREWALL = 'main';

    // CSRF Token Intentions
    public const string CSRF_LOGOUT_INTENTION = 'eurip_sso_logout';

    // Translation Domain
    public const string TRANSLATION_DOMAIN = 'eurip_sso';
}
