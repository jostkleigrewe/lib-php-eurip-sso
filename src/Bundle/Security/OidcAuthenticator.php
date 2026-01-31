<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
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
 * EN: Symfony security authenticator for OIDC login.
 */
final class OidcAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private const SESSION_STATE = '_eurip_sso_state';
    private const SESSION_NONCE = '_eurip_sso_nonce';
    private const SESSION_VERIFIER = '_eurip_sso_verifier';

    /**
     * @param list<string> $scopes
     */
    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly OidcUserProviderInterface $userProvider,
        private readonly array $scopes = ['openid', 'profile', 'email'],
        private readonly string $callbackRoute = '/auth/callback',
        private readonly string $defaultTargetPath = '/',
        private readonly string $loginPath = '/login',
        private readonly bool $verifySignature = false,
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
        $session = $request->getSession();

        // Validate state
        $expectedState = $session->get(self::SESSION_STATE);
        if ($state !== $expectedState) {
            throw new AuthenticationException('Invalid state parameter');
        }

        $codeVerifier = $session->get(self::SESSION_VERIFIER);
        if ($codeVerifier === null) {
            throw new AuthenticationException('Missing code verifier');
        }

        $expectedNonce = $session->get(self::SESSION_NONCE);

        // Clear session data
        $session->remove(self::SESSION_STATE);
        $session->remove(self::SESSION_NONCE);
        $session->remove(self::SESSION_VERIFIER);

        try {
            $tokenResponse = $this->oidcClient->exchangeCode($code, $codeVerifier);
        } catch (TokenExchangeFailedException $e) {
            throw new AuthenticationException('Token exchange failed: ' . $e->error);
        }

        // Get user identifier and validate nonce from ID token
        $userId = $this->extractUserId($tokenResponse, $expectedNonce);

        return new SelfValidatingPassport(
            new UserBadge($userId, fn (string $id) => $this->userProvider->loadOrCreateUser($id, $tokenResponse))
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $targetPath = $request->getSession()->get('_security.' . $firewallName . '.target_path');

        return new RedirectResponse($targetPath ?? $this->defaultTargetPath);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        /** @var \Symfony\Component\HttpFoundation\Session\Session $session */
        $session = $request->getSession();
        $session->getFlashBag()->add('error', $exception->getMessage());

        return new RedirectResponse($this->loginPath);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $authData = $this->oidcClient->buildAuthorizationUrl($this->scopes);

        $session = $request->getSession();
        $session->set(self::SESSION_STATE, $authData['state']);
        $session->set(self::SESSION_NONCE, $authData['nonce']);
        $session->set(self::SESSION_VERIFIER, $authData['code_verifier']);

        return new RedirectResponse($authData['url']);
    }

    private function extractUserId(TokenResponse $tokenResponse, ?string $expectedNonce): string
    {
        if ($tokenResponse->idToken !== null) {
            $claims = $this->oidcClient->decodeIdToken($tokenResponse->idToken, $this->verifySignature);

            // Validate nonce if present
            if ($expectedNonce !== null && isset($claims['nonce']) && $claims['nonce'] !== $expectedNonce) {
                throw new AuthenticationException('Invalid nonce in ID token');
            }

            if (isset($claims['sub'])) {
                return $claims['sub'];
            }
        }

        // Fallback: UserInfo endpoint
        $userInfo = $this->oidcClient->getUserInfo($tokenResponse->accessToken);

        return $userInfo->sub;
    }
}
