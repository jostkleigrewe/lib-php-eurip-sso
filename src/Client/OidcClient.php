<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Client;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Jostkleigrewe\Sso\Contracts\DTO\UserInfoResponse;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * DE: OIDC Client für Authorization Code Flow mit PKCE.
 * EN: OIDC client for authorization code flow with PKCE.
 */
final class OidcClient
{
    public function __construct(
        private readonly OidcClientConfig $config,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly ?string $clientSecret = null,
    ) {
    }

    /**
     * DE: Erstellt die Authorization URL für den Login-Redirect.
     * EN: Creates the authorization URL for login redirect.
     *
     * @param list<string> $scopes
     * @return array{url: string, state: string, nonce: string, code_verifier: string}
     */
    public function buildAuthorizationUrl(array $scopes = ['openid', 'profile', 'email']): array
    {
        $state = $this->generateRandomString(32);
        $nonce = $this->generateRandomString(32);
        $codeVerifier = $this->generateCodeVerifier();
        $codeChallenge = $this->generateCodeChallenge($codeVerifier);

        $params = [
            'response_type' => 'code',
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        $url = $this->config->authorizationEndpoint . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $url,
            'state' => $state,
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
        ];
    }

    /**
     * DE: Tauscht Authorization Code gegen Tokens.
     * EN: Exchanges authorization code for tokens.
     *
     * @throws TokenExchangeFailedException
     */
    public function exchangeCode(string $code, string $codeVerifier): TokenResponse
    {
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->redirectUri,
            'client_id' => $this->config->clientId,
            'code_verifier' => $codeVerifier,
        ];

        if ($this->clientSecret !== null) {
            $params['client_secret'] = $this->clientSecret;
        }

        $response = $this->postForm($this->config->tokenEndpoint, $params);

        if (!isset($response['access_token'])) {
            throw new TokenExchangeFailedException(
                $response['error'] ?? 'unknown_error',
                $response['error_description'] ?? 'Token exchange failed'
            );
        }

        return new TokenResponse(
            accessToken: $response['access_token'],
            idToken: $response['id_token'] ?? null,
            refreshToken: $response['refresh_token'] ?? null,
            expiresIn: (int) ($response['expires_in'] ?? 3600),
            tokenType: $response['token_type'] ?? 'Bearer',
        );
    }

    /**
     * DE: Erneuert Tokens mit Refresh Token.
     * EN: Refreshes tokens using refresh token.
     *
     * @throws TokenExchangeFailedException
     */
    public function refreshToken(string $refreshToken): TokenResponse
    {
        $params = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->config->clientId,
        ];

        if ($this->clientSecret !== null) {
            $params['client_secret'] = $this->clientSecret;
        }

        $response = $this->postForm($this->config->tokenEndpoint, $params);

        if (!isset($response['access_token'])) {
            throw new TokenExchangeFailedException(
                $response['error'] ?? 'unknown_error',
                $response['error_description'] ?? 'Token refresh failed'
            );
        }

        return new TokenResponse(
            accessToken: $response['access_token'],
            idToken: $response['id_token'] ?? null,
            refreshToken: $response['refresh_token'] ?? null,
            expiresIn: (int) ($response['expires_in'] ?? 3600),
            tokenType: $response['token_type'] ?? 'Bearer',
        );
    }

    /**
     * DE: Ruft UserInfo vom IdP ab.
     * EN: Fetches UserInfo from the IdP.
     *
     * @throws OidcProtocolException
     */
    public function getUserInfo(string $accessToken): UserInfoResponse
    {
        $request = $this->requestFactory->createRequest('GET', $this->config->userInfoEndpoint)
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withHeader('Accept', 'application/json');

        $response = $this->httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new OidcProtocolException('UserInfo request failed: ' . $response->getStatusCode());
        }

        $data = json_decode((string) $response->getBody(), true);

        if (!is_array($data) || !isset($data['sub'])) {
            throw new OidcProtocolException('Invalid UserInfo response');
        }

        return new UserInfoResponse(
            sub: $data['sub'],
            email: $data['email'] ?? null,
            name: $data['name'] ?? null,
        );
    }

    /**
     * DE: Dekodiert ID Token Payload (ohne Signaturprüfung).
     * EN: Decodes ID token payload (without signature verification).
     *
     * @return array<string, mixed>
     * @throws OidcProtocolException
     */
    public function decodeIdToken(string $idToken): array
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new OidcProtocolException('Invalid ID token format');
        }

        $payload = json_decode($this->base64UrlDecode($parts[1]), true);

        if (!is_array($payload)) {
            throw new OidcProtocolException('Invalid ID token payload');
        }

        return $payload;
    }

    /**
     * DE: Erstellt Client aus Discovery Document.
     * EN: Creates client from discovery document.
     *
     * @throws OidcProtocolException
     */
    public static function fromDiscovery(
        string $issuer,
        string $clientId,
        string $redirectUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        ?string $clientSecret = null,
    ): self {
        $discoveryUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        $request = $requestFactory->createRequest('GET', $discoveryUrl)
            ->withHeader('Accept', 'application/json');

        $response = $httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new OidcProtocolException('Discovery request failed: ' . $response->getStatusCode());
        }

        $discovery = json_decode((string) $response->getBody(), true);

        if (!is_array($discovery)) {
            throw new OidcProtocolException('Invalid discovery document');
        }

        $config = new OidcClientConfig(
            clientId: $clientId,
            issuer: $discovery['issuer'] ?? $issuer,
            authorizationEndpoint: $discovery['authorization_endpoint'] ?? '',
            tokenEndpoint: $discovery['token_endpoint'] ?? '',
            jwksUri: $discovery['jwks_uri'] ?? '',
            redirectUri: $redirectUri,
            userInfoEndpoint: $discovery['userinfo_endpoint'] ?? '',
        );

        return new self($config, $httpClient, $requestFactory, $streamFactory, $clientSecret);
    }

    /**
     * @return array<string, mixed>
     */
    private function postForm(string $url, array $params): array
    {
        $body = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        $request = $this->requestFactory->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($body));

        $response = $this->httpClient->sendRequest($request);
        $data = json_decode((string) $response->getBody(), true);

        return is_array($data) ? $data : [];
    }

    private function generateRandomString(int $length): string
    {
        return bin2hex(random_bytes($length / 2));
    }

    private function generateCodeVerifier(): string
    {
        // RFC 7636: 43-128 characters
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private function generateCodeChallenge(string $verifier): string
    {
        // S256: BASE64URL(SHA256(verifier))
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/')) ?: '';
    }
}
