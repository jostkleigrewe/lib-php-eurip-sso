<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * DE: Token-Speicher für ID-Token, Access-Token und Refresh-Token.
 *     Speichert Tokens in der Session für Client-Anwendungen.
 * EN: Token storage for ID token, access token, and refresh token.
 *     Stores tokens in session for client applications.
 */
final class EuripSsoTokenStorage
{
    public function __construct(
        private readonly RequestStack $requestStack,
    ) {
    }

    /**
     * DE: Speichert alle Tokens aus einer TokenResponse.
     * EN: Stores all tokens from a TokenResponse.
     */
    public function storeTokens(TokenResponse $tokenResponse): void
    {
        $session = $this->requestStack->getSession();

        // ID-Token is stored separately (already used by AuthenticationController)
        if ($tokenResponse->idToken !== null) {
            $session->set(OidcConstants::SESSION_ID_TOKEN, $tokenResponse->idToken);
        }

        // Access-Token for API calls
        $session->set(OidcConstants::SESSION_ACCESS_TOKEN, $tokenResponse->accessToken);

        // Refresh-Token for token refresh
        if ($tokenResponse->refreshToken !== null) {
            $session->set(OidcConstants::SESSION_REFRESH_TOKEN, $tokenResponse->refreshToken);
        }

        // Expiration time
        $session->set(OidcConstants::SESSION_TOKEN_EXPIRES, $tokenResponse->expiresAt->getTimestamp());
    }

    /**
     * DE: Gibt das ID-Token zurück.
     * EN: Returns the ID token.
     */
    public function getIdToken(): ?string
    {
        $token = $this->requestStack->getSession()->get(OidcConstants::SESSION_ID_TOKEN);
        return is_string($token) ? $token : null;
    }

    /**
     * DE: Gibt das Access-Token zurück.
     * EN: Returns the access token.
     */
    public function getAccessToken(): ?string
    {
        $token = $this->requestStack->getSession()->get(OidcConstants::SESSION_ACCESS_TOKEN);
        return is_string($token) ? $token : null;
    }

    /**
     * DE: Gibt das Refresh-Token zurück.
     * EN: Returns the refresh token.
     */
    public function getRefreshToken(): ?string
    {
        $token = $this->requestStack->getSession()->get(OidcConstants::SESSION_REFRESH_TOKEN);
        return is_string($token) ? $token : null;
    }

    /**
     * DE: Gibt den Ablaufzeitpunkt zurück.
     * EN: Returns the expiration timestamp.
     */
    public function getExpiresAt(): ?\DateTimeImmutable
    {
        $timestamp = $this->requestStack->getSession()->get(OidcConstants::SESSION_TOKEN_EXPIRES);
        if (!is_int($timestamp)) {
            return null;
        }
        return (new \DateTimeImmutable())->setTimestamp($timestamp);
    }

    /**
     * DE: Prüft ob Tokens vorhanden sind.
     * EN: Checks if tokens are present.
     */
    public function hasTokens(): bool
    {
        return $this->getIdToken() !== null || $this->getAccessToken() !== null;
    }

    /**
     * DE: Prüft ob ein gültiges Access-Token vorhanden ist.
     * EN: Checks if a valid access token is present.
     */
    public function hasValidAccessToken(): bool
    {
        if ($this->getAccessToken() === null) {
            return false;
        }

        $expiresAt = $this->getExpiresAt();
        if ($expiresAt === null) {
            return true; // No expiration info, assume valid
        }

        return $expiresAt > new \DateTimeImmutable();
    }

    /**
     * DE: Prüft ob das Access-Token bald abläuft.
     * EN: Checks if the access token expires soon.
     */
    public function isAccessTokenExpiringSoon(int $bufferSeconds = 60): bool
    {
        $expiresAt = $this->getExpiresAt();
        if ($expiresAt === null) {
            return false;
        }

        $bufferTime = (new \DateTimeImmutable())->modify("+{$bufferSeconds} seconds");
        return $expiresAt <= $bufferTime;
    }

    /**
     * DE: Prüft ob ein Refresh-Token vorhanden ist.
     * EN: Checks if a refresh token is present.
     */
    public function canRefresh(): bool
    {
        return $this->getRefreshToken() !== null;
    }

    /**
     * DE: Löscht alle Tokens.
     * EN: Clears all tokens.
     */
    public function clearTokens(): void
    {
        $session = $this->requestStack->getSession();
        $session->remove(OidcConstants::SESSION_ID_TOKEN);
        $session->remove(OidcConstants::SESSION_ACCESS_TOKEN);
        $session->remove(OidcConstants::SESSION_REFRESH_TOKEN);
        $session->remove(OidcConstants::SESSION_TOKEN_EXPIRES);
        $session->remove(OidcConstants::SESSION_SSO_SESSION_STATE);
    }

    /**
     * DE: Speichert den SSO Session State (für Session Management).
     * EN: Stores the SSO session state (for session management).
     */
    public function storeSessionState(string $sessionState): void
    {
        $this->requestStack->getSession()->set(OidcConstants::SESSION_SSO_SESSION_STATE, $sessionState);
    }

    /**
     * DE: Gibt den SSO Session State zurück.
     * EN: Returns the SSO session state.
     */
    public function getSessionState(): ?string
    {
        $state = $this->requestStack->getSession()->get(OidcConstants::SESSION_SSO_SESSION_STATE);
        return is_string($state) ? $state : null;
    }
}
