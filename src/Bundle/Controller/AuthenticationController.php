<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Bundle\Security\OidcSessionStorage;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;
use Jostkleigrewe\Sso\Bundle\Service\OidcAuthenticationService;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcErrorCode;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
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
        private readonly string $defaultTargetPath = '/',
        private readonly string $afterLogoutPath = '/',
        /** @var list<string> */
        private readonly array $scopes = OidcConstants::DEFAULT_SCOPES,
        private readonly string $firewallName = OidcConstants::DEFAULT_FIREWALL,
        private readonly ?EuripSsoTokenStorage $ssoTokenStorage = null,
    ) {
    }

    /**
     * DE: Initiiert den OIDC Login-Flow.
     * EN: Initiates the OIDC login flow.
     */
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
     * DE: Verarbeitet den Callback vom IdP.
     * EN: Processes the callback from the IdP.
     */
    public function callback(Request $request): Response
    {
        $session = $request->getSession();

        // Handle error from IdP (sanitize error description for user display)
        if ($request->query->has('error')) {
            $error = $request->query->getString('error');
            $description = $request->query->getString('error_description', 'Authentication failed');

            // Log full error details (not shown to user)
            $this->logger?->warning('OIDC IdP error', [
                'error' => $error,
                'error_description' => $description,
            ]);

            $failureEvent = $this->authService->dispatchFailure($error, $description);
            if ($failureEvent->hasResponse()) {
                return $failureEvent->getResponse();
            }

            // Show sanitized message to user (no IdP details)
            $this->addFlash('error', $this->getSanitizedErrorMessage($error));
            return $this->redirect($this->afterLogoutPath);
        }

        // Validate required parameters
        $code = $request->query->getString('code');
        $state = $request->query->getString('state');

        if ($code === '' || $state === '') {
            $this->logger?->warning('OIDC callback: Missing required parameters', [
                'has_code' => $code !== '',
                'has_state' => $state !== '',
                'session_debug' => $this->sessionStorage->getDebugInfo(),
            ]);
            $this->addFlash('error', 'Invalid callback parameters');
            return $this->redirect($this->afterLogoutPath);
        }

        $this->logger?->debug('OIDC callback: Processing', [
            'state_prefix' => substr($state, 0, 8) . '...',
            'code_prefix' => substr($code, 0, 8) . '...',
            'session_debug' => $this->sessionStorage->getDebugInfo(),
        ]);

        try {
            $result = $this->authService->handleCallback($code, $state);
            $user = $result['user'];
            $successEvent = $result['event'];
            $idToken = $result['id_token'];

            if ($successEvent->hasResponse()) {
                return $successEvent->getResponse();
            }

            // Store ID token for SSO logout
            if ($idToken !== null) {
                $session->set(OidcConstants::SESSION_ID_TOKEN, $idToken);
            }

            // Store all tokens for API client (if client_services enabled)
            if ($this->ssoTokenStorage !== null) {
                $this->ssoTokenStorage->storeTokens($successEvent->tokenResponse);
            }

            // DE: Session-ID regenerieren um Session Fixation zu verhindern
            // EN: Regenerate session ID to prevent session fixation
            $session->migrate(true);

            // Login user into Symfony security
            $token = new UsernamePasswordToken($user, $this->firewallName, $successEvent->getRoles());
            $this->tokenStorage->setToken($token);
            $session->set('_security_' . $this->firewallName, serialize($token));
            $session->save();

            // Redirect to target
            $targetPath = $successEvent->getTargetPath();
            if ($targetPath === null) {
                $storedReturnUrl = $session->get(OidcConstants::SESSION_RETURN_URL);
                // DE: Type-Check für Session-Wert (könnte manipuliert sein)
                // EN: Type check for session value (could be manipulated)
                $targetPath = (is_string($storedReturnUrl) && $this->isValidReturnUrl($storedReturnUrl))
                    ? $storedReturnUrl
                    : $this->defaultTargetPath;
            }
            $session->remove(OidcConstants::SESSION_RETURN_URL);

            return $this->redirect($targetPath);
        } catch (ClaimsValidationException $e) {
            // Token claims invalid (expired, wrong issuer, nonce mismatch, etc.)
            $this->logger?->warning('OIDC claims validation failed', [
                'claim' => $e->claim,
                'expected' => $e->expected,
                'actual' => $e->actual,
            ]);

            $failureEvent = $this->authService->dispatchFailure('claims_invalid', $e->getMessage(), $e);
            if ($failureEvent->hasResponse()) {
                return $failureEvent->getResponse();
            }

            $this->addFlash('error', $this->getSanitizedErrorMessage('claims_invalid'));
            return $this->redirect($this->afterLogoutPath);
        } catch (TokenExchangeFailedException $e) {
            // Token exchange failed (invalid code, expired code, etc.)
            $this->logger?->warning('OIDC token exchange failed', [
                'error' => $e->error,
            ]);

            $failureEvent = $this->authService->dispatchFailure($e->error, $e->errorDescription, $e);
            if ($failureEvent->hasResponse()) {
                return $failureEvent->getResponse();
            }

            $this->addFlash('error', $this->getSanitizedErrorMessage($e->error));
            return $this->redirect($this->afterLogoutPath);
        } catch (OidcProtocolException $e) {
            // Protocol error (invalid state, missing data, etc.)
            $this->logger?->warning('OIDC protocol error', [
                'message' => $e->getMessage(),
            ]);

            $failureEvent = $this->authService->dispatchFailure('protocol_error', $e->getMessage(), $e);
            if ($failureEvent->hasResponse()) {
                return $failureEvent->getResponse();
            }

            $this->addFlash('error', $this->getSanitizedErrorMessage('protocol_error'));
            return $this->redirect($this->afterLogoutPath);
        } catch (\Throwable $e) {
            // Unexpected error - log full details but don't expose to user
            $this->logger?->error('OIDC unexpected error', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            $failureEvent = $this->authService->dispatchFailure('internal_error', $e->getMessage(), $e);
            if ($failureEvent->hasResponse()) {
                return $failureEvent->getResponse();
            }

            $this->addFlash('error', $this->getSanitizedErrorMessage('internal_error'));
            return $this->redirect($this->afterLogoutPath);
        }
    }

    /**
     * DE: Führt den Logout durch (nur POST mit CSRF-Token).
     * EN: Performs logout (POST only with CSRF token).
     */
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

        $this->addFlash('success', $this->translator->trans('eurip_sso.flash.logout_success', [], 'eurip_sso'));
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

    /**
     * DE: Gibt eine sichere, benutzerfreundliche Fehlermeldung zurück.
     *     Keine technischen Details oder IdP-Informationen.
     * EN: Returns a safe, user-friendly error message.
     *     No technical details or IdP information exposed.
     */
    private function getSanitizedErrorMessage(string $errorCode): string
    {
        $error = OidcErrorCode::fromString($errorCode);

        return $this->translator->trans(
            $error->getTranslationKey(),
            [],
            'eurip_sso',
        );
    }
}
