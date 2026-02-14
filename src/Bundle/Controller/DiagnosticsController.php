<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * DE: Controller für Diagnose-Seiten (debug, test).
 * EN: Controller for diagnostic pages (debug, test).
 */
final class DiagnosticsController extends AbstractController
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        /** @var list<string> */
        #[Autowire('%eurip_sso.scopes%')]
        private readonly array $scopes = OidcConstants::DEFAULT_SCOPES,
        private readonly ?EuripSsoClaimsService $claimsService = null,
        private readonly ?EuripSsoTokenStorage $tokenStorage = null,
    ) {
    }

    /**
     * DE: Zeigt OIDC Debug-Informationen.
     * EN: Shows OIDC debug information.
     */
    #[Route('%eurip_sso.routes.debug%', name: OidcConstants::ROUTE_DEBUG, methods: ['GET'])]
    public function debug(): Response
    {
        $config = $this->oidcClient->getConfig();
        $authData = $this->oidcClient->buildAuthorizationUrl($this->scopes);

        // Collect client services info if available
        $clientServicesData = $this->getClientServicesDebugData();

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
            'client_services' => $clientServicesData,
        ]);
    }

    /**
     * DE: Sammelt Debug-Daten für Client-Services.
     * EN: Collects debug data for client services.
     *
     * @return array<string, mixed>|null
     */
    private function getClientServicesDebugData(): ?array
    {
        if ($this->claimsService === null || $this->tokenStorage === null) {
            return null;
        }

        $data = [
            'enabled' => true,
            'is_authenticated' => $this->claimsService->isAuthenticated(),
            'tokens' => [
                'has_id_token' => $this->tokenStorage->getIdToken() !== null,
                'has_access_token' => $this->tokenStorage->getAccessToken() !== null,
                'has_refresh_token' => $this->tokenStorage->getRefreshToken() !== null,
                'access_token_valid' => $this->tokenStorage->hasValidAccessToken(),
                'expires_at' => $this->tokenStorage->getExpiresAt()?->format('Y-m-d H:i:s'),
            ],
            'claims' => null,
        ];

        if ($this->claimsService->isAuthenticated()) {
            $claims = $this->claimsService->getClaimsOrNull();
            if ($claims !== null) {
                $data['claims'] = [
                    'subject' => $claims->getSubject(),
                    'email' => $claims->getEmail(),
                    'name' => $claims->getName(),
                    'roles' => $claims->getRoles(),
                    'client_roles' => $claims->getClientRoles(),
                    'client_permissions' => $claims->getClientPermissions(),
                    'client_groups' => $claims->getClientGroups(),
                    'is_blocked' => $claims->isBlocked(),
                    'issued_at' => $claims->getIssuedAt()?->format('Y-m-d H:i:s'),
                    'expires_at' => $claims->getExpiresAt()?->format('Y-m-d H:i:s'),
                    'all_claims' => $claims->all(),
                ];
            }
        }

        return $data;
    }

    /**
     * DE: Zeigt Auth-Workflow-Testseite.
     * EN: Shows auth workflow test page.
     */
    #[Route('%eurip_sso.routes.test%', name: OidcConstants::ROUTE_TEST, methods: ['GET'])]
    public function test(): Response
    {
        $user = $this->getUser();
        $config = $this->oidcClient->getConfig();

        // Collect client services info if available
        $clientServicesData = $this->getClientServicesDebugData();

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
            'client_services' => $clientServicesData,
        ]);
    }
}
