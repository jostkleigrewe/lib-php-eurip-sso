<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Bundle\Security\OidcSessionStorage;
use Jostkleigrewe\Sso\Bundle\Service\OidcAuthenticationService;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * DE: Controller für OIDC Authentication (login, callback, logout).
 * EN: Controller for OIDC authentication (login, callback, logout).
 */
final class AuthenticationController extends AbstractController
{
    public function __construct(
        private readonly OidcAuthenticationService $authService,
        private readonly OidcSessionStorage $sessionStorage,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly TranslatorInterface $translator,
        private readonly ?LoggerInterface $logger = null,
        #[Autowire('%eurip_sso.routes.after_login%')]
        private readonly string $defaultTargetPath = '/',
        #[Autowire('%eurip_sso.routes.after_logout%')]
        private readonly string $afterLogoutPath = '/',
        /** @var list<string> */
        #[Autowire('%eurip_sso.scopes%')]
        private readonly array $scopes = OidcConstants::DEFAULT_SCOPES,
    ) {
    }

    /**
     * DE: Initiiert den OIDC Login-Flow.
     * EN: Initiates the OIDC login flow.
     */
    #[Route('%eurip_sso.routes.login%', name: OidcConstants::ROUTE_LOGIN, methods: ['GET'])]
    public function login(Request $request): Response
    {
        // Already logged in?
        if ($this->getUser() !== null) {
            $this->logger?->debug('OIDC login: User already logged in, redirecting', [
                'user' => $this->getUser()->getUserIdentifier(),
            ]);
            return $this->redirect($this->defaultTargetPath);
        }

        // Get pre-login event (allows cancellation or scope modification)
        $preLoginEvent = $this->authService->getPreLoginEvent($request, $this->scopes);
        if ($preLoginEvent->hasResponse()) {
            $this->logger?->debug('OIDC login: Pre-login event provided custom response');
            return $preLoginEvent->getResponse();
        }

        // DE: Prüfe ob bereits ein gültiger State existiert (Doppelklick-Schutz)
        // EN: Check if valid state already exists (double-click protection)
        $existingState = $this->sessionStorage->getValidState();
        if ($existingState !== null) {
            $this->logger?->info('OIDC login: Reusing existing state (double-click protection)', [
                'state_prefix' => substr($existingState['state'], 0, 8) . '...',
                'session_debug' => $this->sessionStorage->getDebugInfo(),
            ]);

            // DE: Baue URL mit bestehendem State // EN: Build URL with existing state
            $authUrl = $this->authService->getClient()->buildAuthorizationUrlWithState(
                $existingState['state'],
                $existingState['nonce'],
                $existingState['verifier'],
                $preLoginEvent->getScopes(),
            );

            return new RedirectResponse($authUrl);
        }

        // Build authorization URL with new state
        $authData = $this->authService->getClient()->buildAuthorizationUrl($preLoginEvent->getScopes());

        // DE: State in Session speichern (inkl. Expire-Zeit für Retry-Logik)
        // EN: Store state in session (including expire time for retry logic)
        $this->sessionStorage->store(
            state: $authData['state'],
            nonce: $authData['nonce'],
            verifier: $authData['code_verifier'],
        );

        // Store return URL if provided (validate to prevent open redirect)
        $returnUrl = $request->query->get('return');
        if ($returnUrl !== null && $this->isValidReturnUrl($returnUrl)) {
            $request->getSession()->set(OidcConstants::SESSION_RETURN_URL, $returnUrl);
        }

        $this->logger?->debug('OIDC login initiated', [
            'redirect_to' => parse_url($authData['url'], PHP_URL_HOST),
            'state_prefix' => substr($authData['state'], 0, 8) . '...',
            'session_debug' => $this->sessionStorage->getDebugInfo(),
        ]);

        return new RedirectResponse($authData['url']);
    }

    /**
     * DE: Callback-Route vom IdP — wird vom OidcAuthenticator abgefangen.
     *     Wirft LogicException falls der Authenticator nicht aktiv ist (wie Symfony json_login).
     * EN: Callback route from IdP — intercepted by OidcAuthenticator.
     *     Throws LogicException if the authenticator is not active (like Symfony json_login).
     */
    #[Route('%eurip_sso.routes.callback%', name: OidcConstants::ROUTE_CALLBACK, methods: ['GET'])]
    public function callback(Request $request): never
    {
        throw new \LogicException(
            'This controller action should be handled by the OidcAuthenticator. '
            . 'Make sure the authenticator is enabled in your security configuration.'
        );
    }

    /**
     * DE: Zeigt eine Bestätigungsseite für den Logout (GET).
     *     Ermöglicht einfache Links statt POST-Forms.
     * EN: Shows a logout confirmation page (GET).
     *     Allows simple links instead of POST forms.
     */
    #[Route('%eurip_sso.routes.logout_confirm%', name: OidcConstants::ROUTE_LOGOUT_CONFIRM, methods: ['GET'])]
    public function logoutConfirm(Request $request): Response
    {
        // DE: Nicht eingeloggt? Direkt zur Startseite
        // EN: Not logged in? Redirect to home
        $user = $this->getUser();
        if ($user === null) {
            return $this->redirect($this->afterLogoutPath);
        }

        // DE: Cancel-URL validieren (Open Redirect Prevention)
        // EN: Validate cancel URL (open redirect prevention)
        $referer = $request->headers->get('referer');
        $cancelUrl = ($referer !== null && $this->isValidReturnUrl(parse_url($referer, PHP_URL_PATH) ?? ''))
            ? $referer
            : $this->defaultTargetPath;

        return $this->render('@EuripSso/logout_confirm.html.twig', [
            'user' => $user,
            'cancel_url' => $cancelUrl,
        ]);
    }

    /**
     * DE: Führt den Logout durch (nur POST mit CSRF-Token).
     * EN: Performs logout (POST only with CSRF token).
     */
    #[Route('%eurip_sso.routes.logout%', name: OidcConstants::ROUTE_LOGOUT, methods: ['POST'])]
    public function logout(Request $request): Response
    {
        // DE: CSRF-Token validieren um Logout-CSRF zu verhindern
        // EN: Validate CSRF token to prevent logout CSRF attacks
        $csrfToken = $request->request->getString('_csrf_token');
        if (!$this->isCsrfTokenValid(OidcConstants::CSRF_LOGOUT_INTENTION, $csrfToken)) {
            $this->logger?->warning('OIDC logout: Invalid CSRF token');
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }

        $session = $request->getSession();
        $idToken = $session->get(OidcConstants::SESSION_ID_TOKEN);
        $user = $this->getUser();

        // Prepare logout (dispatch event, get logout URL)
        $logoutUrl = $this->authService->prepareLogout(
            $request,
            $user,
            $idToken,
            $request->getSchemeAndHttpHost() . $this->afterLogoutPath,
        );

        // Clear security token BEFORE invalidating session
        $this->tokenStorage->setToken(null);

        // Invalidate session
        $session->invalidate();

        // Redirect to SSO logout or local
        if ($logoutUrl !== null) {
            return new RedirectResponse($logoutUrl);
        }

        $this->addFlash('success', $this->translator->trans('eurip_sso.flash.logout_success', [], OidcConstants::TRANSLATION_DOMAIN));
        return $this->redirect($this->afterLogoutPath);
    }

    /**
     * DE: Validiert Return-URL gegen Open Redirect.
     * EN: Validates return URL against open redirect.
     */
    private function isValidReturnUrl(string $url): bool
    {
        if (!str_starts_with($url, '/')) {
            return false;
        }
        if (str_starts_with($url, '//')) {
            return false;
        }
        if (preg_match('/[\r\n]/', $url)) {
            return false;
        }
        return true;
    }
}
