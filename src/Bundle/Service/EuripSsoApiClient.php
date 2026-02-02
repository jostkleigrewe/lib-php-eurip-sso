<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

use Jostkleigrewe\Sso\Bundle\DTO\SsoClaims;
use Jostkleigrewe\Sso\Bundle\Exception\NotAuthenticatedException;
use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Jostkleigrewe\Sso\Contracts\DTO\UserInfoResponse;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * DE: API-Client für Calls zum SSO Server mit Bearer-Token.
 *     Ermöglicht UserInfo-Abruf und Token-Refresh.
 * EN: API client for calls to SSO Server with bearer token.
 *     Enables UserInfo fetch and token refresh.
 */
final class EuripSsoApiClient
{
    public function __construct(
        private readonly EuripSsoTokenStorage $tokenStorage,
        private readonly EuripSsoClaimsService $claimsService,
        private readonly OidcClient $oidcClient,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * DE: Ruft frische UserInfo vom SSO Server ab.
     * EN: Fetches fresh UserInfo from the SSO server.
     *
     * @throws NotAuthenticatedException wenn kein Access-Token vorhanden
     * @throws OidcProtocolException bei API-Fehlern
     */
    public function getUserInfo(): UserInfoResponse
    {
        $accessToken = $this->getAccessTokenOrThrow();
        return $this->oidcClient->getUserInfo($accessToken);
    }

    /**
     * DE: Erneuert das Access-Token mit dem Refresh-Token.
     * EN: Refreshes the access token using the refresh token.
     *
     * @throws NotAuthenticatedException wenn kein Refresh-Token vorhanden
     * @throws TokenExchangeFailedException bei Refresh-Fehlern
     */
    public function refreshTokens(): TokenResponse
    {
        $refreshToken = $this->tokenStorage->getRefreshToken();
        if ($refreshToken === null) {
            throw new NotAuthenticatedException('No refresh token available.');
        }

        $tokenResponse = $this->oidcClient->refreshToken($refreshToken);

        // Store new tokens
        $this->tokenStorage->storeTokens($tokenResponse);

        // Clear claims cache
        $this->claimsService->clearCache();

        // Dispatch event
        $this->eventDispatcher->dispatch(
            new \Jostkleigrewe\Sso\Bundle\Event\OidcTokenRefreshedEvent($tokenResponse),
            OidcConstants::EVENT_TOKEN_REFRESHED
        );

        $this->logger?->info('Tokens refreshed successfully');

        return $tokenResponse;
    }

    /**
     * DE: Aktualisiert Claims durch Token-Refresh und gibt neue Claims zurück.
     * EN: Updates claims through token refresh and returns new claims.
     *
     * @throws NotAuthenticatedException wenn kein Refresh-Token vorhanden
     * @throws TokenExchangeFailedException bei Refresh-Fehlern
     */
    public function refreshClaims(): SsoClaims
    {
        $tokenResponse = $this->refreshTokens();

        // ID-Token might be in the refresh response
        if ($tokenResponse->idToken !== null) {
            $claims = $this->oidcClient->decodeIdToken(
                idToken: $tokenResponse->idToken,
                verifySignature: false,
                validateClaims: false,
            );
            return new SsoClaims($claims);
        }

        // Otherwise return current claims from storage
        return $this->claimsService->getClaims();
    }

    /**
     * DE: Prüft ob ein gültiges Access-Token vorhanden ist.
     * EN: Checks if a valid access token is present.
     */
    public function hasValidAccessToken(): bool
    {
        return $this->tokenStorage->hasValidAccessToken();
    }

    /**
     * DE: Gibt das Access-Token zurück (oder null).
     * EN: Returns the access token (or null).
     */
    public function getAccessToken(): ?string
    {
        return $this->tokenStorage->getAccessToken();
    }

    /**
     * DE: Gibt das Access-Token zurück oder wirft Exception.
     * EN: Returns the access token or throws exception.
     *
     * @throws NotAuthenticatedException
     */
    public function getAccessTokenOrThrow(): string
    {
        $accessToken = $this->tokenStorage->getAccessToken();
        if ($accessToken === null) {
            throw new NotAuthenticatedException('No access token available.');
        }
        return $accessToken;
    }

    /**
     * DE: Prüft ob ein Refresh-Token vorhanden ist.
     * EN: Checks if a refresh token is present.
     */
    public function canRefresh(): bool
    {
        return $this->tokenStorage->canRefresh();
    }

    /**
     * DE: Prüft ob das Access-Token bald abläuft.
     * EN: Checks if the access token expires soon.
     */
    public function isAccessTokenExpiringSoon(int $bufferSeconds = 60): bool
    {
        return $this->tokenStorage->isAccessTokenExpiringSoon($bufferSeconds);
    }

    /**
     * DE: Erneuert Token automatisch wenn es bald abläuft und Refresh möglich ist.
     * EN: Automatically refreshes token if it expires soon and refresh is possible.
     *
     * @return bool True wenn Token erneuert wurde
     */
    public function refreshIfNeeded(int $bufferSeconds = 60): bool
    {
        if (!$this->isAccessTokenExpiringSoon($bufferSeconds)) {
            return false;
        }

        if (!$this->canRefresh()) {
            return false;
        }

        try {
            $this->refreshTokens();
            return true;
        } catch (TokenExchangeFailedException $e) {
            $this->logger?->warning('Auto-refresh failed', ['error' => $e->getMessage()]);
            return false;
        }
    }
}
