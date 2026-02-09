<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;
use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;
use Jostkleigrewe\Sso\Bundle\Service\OidcAuthenticationService;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcAuthenticationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * DE: Symfony Security Authenticator für OIDC Login.
 *     Delegiert Business-Logik an OidcAuthenticationService, mapped Exceptions.
 * EN: Symfony security authenticator for OIDC login.
 *     Delegates business logic to OidcAuthenticationService, maps exceptions.
 */
final class OidcAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private ?OidcLoginSuccessEvent $lastSuccessEvent = null;
    private ?string $lastIdToken = null;

    /**
     * @param list<string> $scopes
     */
    public function __construct(
        private readonly OidcAuthenticationService $authService,
        private readonly OidcSessionStorage $sessionStorage,
        private readonly ?EuripSsoTokenStorage $ssoTokenStorage = null,
        private readonly ?LoggerInterface $logger = null,
        #[Autowire('%eurip_sso.routes.callback%')]
        private readonly string $callbackRoute = '/auth/callback',
        #[Autowire('%eurip_sso.routes.after_login%')]
        private readonly string $defaultTargetPath = '/',
        #[Autowire('%eurip_sso.routes.login%')]
        private readonly string $loginPath = '/login',
        /** @var list<string> */
        #[Autowire('%eurip_sso.scopes%')]
        private readonly array $scopes = OidcConstants::DEFAULT_SCOPES,
    ) {
    }

    public function supports(Request $request): bool
    {
        return $request->getPathInfo() === $this->callbackRoute
            && $request->query->has('code');
    }

    public function authenticate(Request $request): Passport
    {
        $code = $request->query->getString('code');
        $state = $request->query->getString('state');

        if ($code === '' || $state === '') {
            throw OidcAuthenticationException::fromProtocol(
                new OidcProtocolException('Missing required callback parameters')
            );
        }

        try {
            $result = $this->authService->handleCallback($code, $state);
        } catch (ClaimsValidationException $e) {
            throw OidcAuthenticationException::fromClaimsValidation($e);
        } catch (TokenExchangeFailedException $e) {
            throw OidcAuthenticationException::fromTokenExchange($e);
        } catch (OidcProtocolException $e) {
            throw OidcAuthenticationException::fromProtocol($e);
        } catch (\Throwable $e) {
            throw OidcAuthenticationException::fromInternal($e);
        }

        $user = $result['user'];
        $this->lastSuccessEvent = $result['event'];
        $this->lastIdToken = $result['id_token'];

        return new SelfValidatingPassport(
            new UserBadge($user->getUserIdentifier(), static fn () => $user)
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        // DE: Tokens für API-Client speichern // EN: Store tokens for API client
        if ($this->ssoTokenStorage !== null && $this->lastSuccessEvent !== null) {
            $this->ssoTokenStorage->storeTokens($this->lastSuccessEvent->tokenResponse);
        }

        // DE: ID-Token für SSO-Logout speichern // EN: Store ID token for SSO logout
        if ($this->lastIdToken !== null) {
            $request->getSession()->set(OidcConstants::SESSION_ID_TOKEN, $this->lastIdToken);
        }

        // DE: Custom Response aus Event (z.B. Login blockieren) // EN: Custom response from event (e.g. block login)
        if ($this->lastSuccessEvent?->hasResponse()) {
            return $this->lastSuccessEvent->getResponse();
        }

        $targetPath = $this->lastSuccessEvent?->getTargetPath()
            ?? $request->getSession()->get('_security.' . $firewallName . '.target_path')
            ?? $this->defaultTargetPath;

        return new RedirectResponse($targetPath);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        if ($exception instanceof OidcAuthenticationException) {
            $this->logger?->warning('OIDC authentication failed', [
                'error_code' => $exception->errorCode->value,
                'message' => $exception->getMessage(),
            ]);

            // DE: Failure-Event dispatchen für Event-Listener // EN: Dispatch failure event for event listeners
            $this->authService->dispatchFailure(
                $exception->errorCode->value,
                $exception->getMessage(),
                $exception->originalException,
            );
        }

        /** @var \Symfony\Component\HttpFoundation\Session\Session $session */
        $session = $request->getSession();
        $session->getFlashBag()->add('error', $exception->getMessageKey());

        return new RedirectResponse($this->loginPath);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        // DE: Doppelklick-Schutz: bestehenden State wiederverwenden
        // EN: Double-click protection: reuse existing state
        $existingState = $this->sessionStorage->getValidState();
        if ($existingState !== null) {
            $authUrl = $this->authService->getClient()->buildAuthorizationUrlWithState(
                $existingState['state'],
                $existingState['nonce'],
                $existingState['verifier'],
                $this->scopes,
            );

            return new RedirectResponse($authUrl);
        }

        $authData = $this->authService->getClient()->buildAuthorizationUrl($this->scopes);

        $this->sessionStorage->store(
            state: $authData['state'],
            nonce: $authData['nonce'],
            verifier: $authData['code_verifier'],
        );

        return new RedirectResponse($authData['url']);
    }
}
