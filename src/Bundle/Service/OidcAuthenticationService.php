<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

use Jostkleigrewe\Sso\Bundle\Event\OidcLoginFailureEvent;
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;
use Jostkleigrewe\Sso\Bundle\Event\OidcPreLoginEvent;
use Jostkleigrewe\Sso\Bundle\Event\OidcPreLogoutEvent;
use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Bundle\Security\OidcSessionStorage;
use Jostkleigrewe\Sso\Bundle\Security\OidcUserProviderInterface;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * DE: Service für OIDC Authentication Business-Logik.
 *     Wird von Controller und Authenticator verwendet.
 * EN: Service for OIDC authentication business logic.
 *     Used by controller and authenticator.
 */
final class OidcAuthenticationService
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly OidcUserProviderInterface $userProvider,
        private readonly OidcSessionStorage $sessionStorage,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly ?OidcCacheService $cacheService = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * DE: Initiiert den Login-Flow.
     * EN: Initiates the login flow.
     *
     * @param list<string> $scopes
     * @return array{url: string, scopes: list<string>}|null Null wenn Event abgebrochen hat
     */
    public function initiateLogin(Request $request, array $scopes = OidcConstants::DEFAULT_SCOPES): ?array
    {
        // Dispatch pre-login event
        $preLoginEvent = new OidcPreLoginEvent($request, $scopes);
        $this->eventDispatcher->dispatch($preLoginEvent);

        if ($preLoginEvent->hasResponse()) {
            return null; // Event handler wants to handle response
        }

        // Build authorization URL with PKCE
        $authData = $this->oidcClient->buildAuthorizationUrl($preLoginEvent->getScopes());

        // Store state, nonce, verifier in session
        $this->sessionStorage->store(
            state: $authData['state'],
            nonce: $authData['nonce'],
            verifier: $authData['code_verifier'],
        );

        $this->logger?->debug('OIDC login initiated', [
            'redirect_to' => parse_url($authData['url'], PHP_URL_HOST),
        ]);

        return [
            'url' => $authData['url'],
            'scopes' => $preLoginEvent->getScopes(),
        ];
    }

    /**
     * DE: Verarbeitet den Callback vom IdP.
     * EN: Processes the callback from the IdP.
     *
     * @return array{user: UserInterface, event: OidcLoginSuccessEvent, id_token: string|null}
     * @throws TokenExchangeFailedException
     * @throws ClaimsValidationException
     * @throws OidcProtocolException
     */
    public function handleCallback(string $code, string $state): array
    {
        $this->logger?->debug('OIDC handleCallback: Starting', [
            'state_prefix' => substr($state, 0, 8) . '...',
            'code_prefix' => substr($code, 0, 8) . '...',
            'session_debug' => $this->sessionStorage->getDebugInfo(),
        ]);

        // Validate state and get stored data
        $storedData = $this->sessionStorage->validateAndClear($state);
        if ($storedData === null) {
            $this->logger?->warning('OIDC state validation failed', [
                'received_state_prefix' => substr($state, 0, 8) . '...',
                'session_debug' => $this->sessionStorage->getDebugInfo(),
            ]);
            throw new OidcProtocolException('Invalid session state');
        }

        $this->logger?->debug('OIDC handleCallback: State validated, exchanging code');

        // DE: State wurde bereits in validateAndClear() als "used" markiert
        //     um Race Conditions zu verhindern (kein Retry bei parallelen Requests)
        // EN: State was already marked as "used" in validateAndClear()
        //     to prevent race conditions (no retry with parallel requests)

        // Exchange code for tokens
        try {
            $tokenResponse = $this->oidcClient->exchangeCode($code, $storedData['verifier']);
        } catch (TokenExchangeFailedException $e) {
            // DE: Bei invalid_client den Cache clearen, damit der nächste Login funktioniert.
            //     Ein automatischer Retry ist nicht möglich, da der State bereits verbraucht wurde.
            // EN: On invalid_client clear cache so next login works.
            //     Automatic retry not possible since state was already consumed.
            if ($e->error === 'invalid_client' && $this->cacheService !== null) {
                $this->logger?->warning('OIDC token exchange failed with invalid_client, clearing cache', [
                    'error_description' => $e->errorDescription,
                ]);
                $this->cacheService->clearAll();
            }
            throw $e;
        }

        // Decode and validate ID token
        $claims = [];
        $idToken = null;
        if ($tokenResponse->idToken !== null) {
            $claims = $this->oidcClient->decodeIdToken($tokenResponse->idToken);
            $this->oidcClient->validateClaims($claims, $storedData['nonce']);
            $idToken = $tokenResponse->idToken;
        }

        // Provision user
        $user = $this->userProvider->loadOrCreateUser($claims, $tokenResponse);

        // Dispatch success event
        $successEvent = new OidcLoginSuccessEvent($user, $tokenResponse, $claims);
        $this->eventDispatcher->dispatch($successEvent);

        // Clear auth state after successful login (prevents replay)
        $this->sessionStorage->markSuccessAndClear();

        $this->logger?->info('OIDC login successful', [
            'user' => $user->getUserIdentifier(),
        ]);

        return [
            'user' => $user,
            'event' => $successEvent,
            'id_token' => $idToken,
        ];
    }

    /**
     * DE: Bereitet den Logout vor und gibt die Logout-URL zurück.
     * EN: Prepares logout and returns the logout URL.
     *
     * @return string|null Logout-URL oder null wenn nur lokaler Logout
     */
    public function prepareLogout(
        Request $request,
        ?UserInterface $user,
        ?string $idToken,
        string $postLogoutRedirectUri,
    ): ?string {
        // Dispatch pre-logout event
        $preLogoutEvent = new OidcPreLogoutEvent($request, $user, $idToken);
        $this->eventDispatcher->dispatch($preLogoutEvent);

        if ($preLogoutEvent->hasResponse() || $preLogoutEvent->shouldSkipSsoLogout()) {
            return null;
        }

        $this->logger?->debug('OIDC logout initiated');

        // Try to build SSO logout URL
        try {
            return $this->oidcClient->buildLogoutUrl(
                postLogoutRedirectUri: $postLogoutRedirectUri,
                idTokenHint: $idToken,
            );
        } catch (OidcProtocolException) {
            // No end_session_endpoint configured
            return null;
        }
    }

    /**
     * DE: Dispatcht ein Login-Failure-Event.
     * EN: Dispatches a login failure event.
     */
    public function dispatchFailure(string $error, string $description, ?\Throwable $exception = null): OidcLoginFailureEvent
    {
        $this->logger?->warning('OIDC login failed', [
            'error' => $error,
            'description' => $description,
        ]);

        $event = new OidcLoginFailureEvent($error, $description, $exception);
        $this->eventDispatcher->dispatch($event);

        return $event;
    }

    /**
     * DE: Gibt den OidcClient zurück (für Debug-Zwecke).
     * EN: Returns the OidcClient (for debug purposes).
     */
    public function getClient(): OidcClient
    {
        return $this->oidcClient;
    }

    /**
     * DE: Gibt den Pre-Login Event zurück falls vorhanden.
     * EN: Returns the pre-login event if available.
     *
     * @param list<string> $scopes
     */
    public function getPreLoginEvent(Request $request, array $scopes): OidcPreLoginEvent
    {
        $event = new OidcPreLoginEvent($request, $scopes);
        $this->eventDispatcher->dispatch($event);
        return $event;
    }
}
