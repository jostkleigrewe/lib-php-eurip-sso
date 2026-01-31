<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle;

/**
 * DE: Konstanten für das OIDC SSO Bundle.
 * EN: Constants for the OIDC SSO bundle.
 */
interface OidcConstants
{
    // Session Keys
    public const SESSION_STATE = '_eurip_sso_state';
    public const SESSION_NONCE = '_eurip_sso_nonce';
    public const SESSION_VERIFIER = '_eurip_sso_verifier';
    public const SESSION_ID_TOKEN = '_eurip_sso_id_token';
    public const SESSION_RETURN_URL = '_eurip_sso_return_url';

    // Event Names
    public const EVENT_PRE_LOGIN = 'eurip_sso.login.pre';
    public const EVENT_LOGIN_SUCCESS = 'eurip_sso.login.success';
    public const EVENT_LOGIN_FAILURE = 'eurip_sso.login.failure';
    public const EVENT_PRE_LOGOUT = 'eurip_sso.logout.pre';
    public const EVENT_USER_CREATED = 'eurip_sso.user.created';
    public const EVENT_USER_UPDATED = 'eurip_sso.user.updated';
    public const EVENT_TOKEN_REFRESHED = 'eurip_sso.token.refreshed';

    // Route Names
    public const ROUTE_LOGIN = 'eurip_sso_login';
    public const ROUTE_CALLBACK = 'eurip_sso_callback';
    public const ROUTE_LOGOUT = 'eurip_sso_logout';
    public const ROUTE_PROFILE = 'eurip_sso_profile';
    public const ROUTE_DEBUG = 'eurip_sso_debug';
    public const ROUTE_TEST = 'eurip_sso_test';

    // Default Scopes
    public const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

    // Default Firewall
    public const DEFAULT_FIREWALL = 'main';
}
