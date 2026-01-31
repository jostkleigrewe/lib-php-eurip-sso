<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;

/**
 * DE: Controller für Diagnose-Seiten (debug, test).
 * EN: Controller for diagnostic pages (debug, test).
 */
final class DiagnosticsController extends AbstractController
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        /** @var list<string> */
        private readonly array $scopes = OidcConstants::DEFAULT_SCOPES,
    ) {
    }

    /**
     * DE: Zeigt OIDC Debug-Informationen.
     * EN: Shows OIDC debug information.
     */
    public function debug(): Response
    {
        $config = $this->oidcClient->getConfig();
        $authData = $this->oidcClient->buildAuthorizationUrl($this->scopes);

        return $this->render('@EuripSso/debug.html.twig', [
            'config' => [
                'issuer' => $config->issuer,
                'public_issuer' => $config->getPublicIssuer(),
                'client_id' => $config->clientId,
                'redirect_uri' => $config->redirectUri,
                'scopes' => $this->scopes,
                'authorization_endpoint' => $config->authorizationEndpoint,
                'token_endpoint' => $config->tokenEndpoint,
                'userinfo_endpoint' => $config->userInfoEndpoint,
                'jwks_uri' => $config->jwksUri,
                'end_session_endpoint' => $config->endSessionEndpoint,
            ],
            'auth_url_preview' => $authData['url'],
            'user' => $this->getUser(),
        ]);
    }

    /**
     * DE: Zeigt Auth-Workflow-Testseite.
     * EN: Shows auth workflow test page.
     */
    public function test(): Response
    {
        $user = $this->getUser();
        $config = $this->oidcClient->getConfig();

        return $this->render('@EuripSso/test.html.twig', [
            'user' => $user,
            'is_authenticated' => $user !== null,
            'routes' => [
                'login' => OidcConstants::ROUTE_LOGIN,
                'callback' => OidcConstants::ROUTE_CALLBACK,
                'logout' => OidcConstants::ROUTE_LOGOUT,
                'profile' => OidcConstants::ROUTE_PROFILE,
                'debug' => OidcConstants::ROUTE_DEBUG,
                'test' => OidcConstants::ROUTE_TEST,
            ],
            'config' => [
                'issuer' => $config->issuer,
                'client_id' => $config->clientId,
                'scopes' => $this->scopes,
            ],
            'workflow_steps' => [
                [
                    'step' => 1,
                    'name' => 'Login initiieren',
                    'description' => 'Klick auf Login → Redirect zum IdP mit state/nonce/PKCE',
                    'route' => OidcConstants::ROUTE_LOGIN,
                    'status' => $user !== null ? 'done' : 'pending',
                ],
                [
                    'step' => 2,
                    'name' => 'IdP Authentication',
                    'description' => 'User authentifiziert sich beim Identity Provider',
                    'route' => null,
                    'status' => $user !== null ? 'done' : 'waiting',
                ],
                [
                    'step' => 3,
                    'name' => 'Callback verarbeiten',
                    'description' => 'Authorization Code empfangen, Token Exchange, User Provisioning',
                    'route' => OidcConstants::ROUTE_CALLBACK,
                    'status' => $user !== null ? 'done' : 'waiting',
                ],
                [
                    'step' => 4,
                    'name' => 'Session erstellt',
                    'description' => 'User ist eingeloggt, Symfony Security Token gesetzt',
                    'route' => null,
                    'status' => $user !== null ? 'done' : 'waiting',
                ],
            ],
        ]);
    }
}
