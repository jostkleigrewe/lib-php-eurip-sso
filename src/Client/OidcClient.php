<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Client;

use Jostkleigrewe\Sso\Contracts\DTO\DeviceCodePollResult;
use Jostkleigrewe\Sso\Contracts\DTO\DeviceCodeResponse;
use Jostkleigrewe\Sso\Contracts\DTO\IntrospectionResponse;
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Jostkleigrewe\Sso\Contracts\DTO\UserInfoResponse;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * DE: OIDC Client für Authorization Code Flow mit PKCE.
 * EN: OIDC client for authorization code flow with PKCE.
 */
final class OidcClient
{
    private const CLOCK_SKEW_SECONDS = 30;

    private LoggerInterface $logger;

    public function __construct(
        private readonly OidcClientConfig $config,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly JwtVerifier $jwtVerifier,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * DE: Gibt die Client-Konfiguration zurück.
     * EN: Returns the client configuration.
     */
    public function getConfig(): OidcClientConfig
    {
        return $this->config;
    }

    /**
     * DE: Gibt den JwtVerifier zurück.
     * EN: Returns the JWT verifier.
     */
    public function getJwtVerifier(): JwtVerifier
    {
        return $this->jwtVerifier;
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

        $this->logger->debug('Built authorization URL', [
            'client_id' => $this->config->clientId,
            'scopes' => $scopes,
        ]);

        return [
            'url' => $url,
            'state' => $state,
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
        ];
    }

    /**
     * DE: Erstellt die Authorization URL mit bestehendem State (für Doppelklick-Schutz).
     * EN: Creates the authorization URL with existing state (for double-click protection).
     *
     * @param list<string> $scopes
     */
    public function buildAuthorizationUrlWithState(
        string $state,
        string $nonce,
        string $codeVerifier,
        array $scopes = ['openid', 'profile', 'email'],
    ): string {
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

        $this->logger->debug('Built authorization URL with existing state', [
            'client_id' => $this->config->clientId,
            'scopes' => $scopes,
            'state_prefix' => substr($state, 0, 8) . '...',
        ]);

        return $url;
    }

    /**
     * DE: Erstellt die Logout-URL für SSO-Logout.
     * EN: Creates the logout URL for SSO logout.
     *
     * @throws OidcProtocolException wenn kein end_session_endpoint konfiguriert ist
     */
    public function buildLogoutUrl(?string $postLogoutRedirectUri = null, ?string $idTokenHint = null): string
    {
        if ($this->config->endSessionEndpoint === null) {
            throw new OidcProtocolException('No end_session_endpoint configured');
        }

        $params = [];

        if ($postLogoutRedirectUri !== null) {
            $params['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }

        if ($idTokenHint !== null) {
            $params['id_token_hint'] = $idTokenHint;
        }

        if ($params === []) {
            return $this->config->endSessionEndpoint;
        }

        return $this->config->endSessionEndpoint . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * DE: Tauscht Authorization Code gegen Tokens.
     * EN: Exchanges authorization code for tokens.
     *
     * @throws TokenExchangeFailedException
     * @throws \InvalidArgumentException wenn code oder codeVerifier leer ist
     */
    public function exchangeCode(string $code, string $codeVerifier): TokenResponse
    {
        // DE: Eingabevalidierung // EN: Input validation
        if ($code === '') {
            throw new \InvalidArgumentException('Authorization code must not be empty');
        }
        if ($codeVerifier === '') {
            throw new \InvalidArgumentException('Code verifier must not be empty');
        }

        $this->logger->debug('Exchanging authorization code for tokens');

        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->redirectUri,
            'client_id' => $this->config->clientId,
            'code_verifier' => $codeVerifier,
        ];

        if ($this->config->clientSecret !== null) {
            $params['client_secret'] = $this->config->clientSecret;
        }

        $response = $this->postForm($this->config->tokenEndpoint, $params);

        if (!isset($response['access_token'])) {
            $error = $response['error'] ?? 'unknown_error';
            $description = $response['error_description'] ?? 'Token exchange failed';

            $this->logger->error('Token exchange failed', [
                'error' => $error,
                'error_description' => $description,
            ]);

            throw new TokenExchangeFailedException($error, $description);
        }

        $this->logger->info('Token exchange successful');

        return TokenResponse::fromArray($response);
    }

    /**
     * DE: Erneuert Tokens mit Refresh Token.
     * EN: Refreshes tokens using refresh token.
     *
     * @throws TokenExchangeFailedException
     */
    public function refreshToken(string $refreshToken): TokenResponse
    {
        $this->logger->debug('Refreshing tokens');

        $params = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->config->clientId,
        ];

        if ($this->config->clientSecret !== null) {
            $params['client_secret'] = $this->config->clientSecret;
        }

        $response = $this->postForm($this->config->tokenEndpoint, $params);

        if (!isset($response['access_token'])) {
            $error = $response['error'] ?? 'unknown_error';
            $description = $response['error_description'] ?? 'Token refresh failed';

            $this->logger->error('Token refresh failed', [
                'error' => $error,
                'error_description' => $description,
            ]);

            throw new TokenExchangeFailedException($error, $description);
        }

        $this->logger->info('Token refresh successful');

        return TokenResponse::fromArray($response);
    }

    /**
     * DE: Ruft UserInfo vom IdP ab.
     * EN: Fetches UserInfo from the IdP.
     *
     * @throws OidcProtocolException
     */
    public function getUserInfo(string $accessToken): UserInfoResponse
    {
        $this->logger->debug('Fetching user info');

        $request = $this->requestFactory->createRequest('GET', $this->config->userInfoEndpoint)
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withHeader('Accept', 'application/json');

        $response = $this->httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            $this->logger->error('UserInfo request failed', [
                'status_code' => $response->getStatusCode(),
            ]);
            throw new OidcProtocolException('UserInfo request failed: ' . $response->getStatusCode());
        }

        $data = json_decode((string) $response->getBody(), true);

        if (!is_array($data) || !isset($data['sub'])) {
            throw new OidcProtocolException('Invalid UserInfo response');
        }

        $this->logger->debug('UserInfo fetched successfully', ['sub' => $data['sub']]);

        return UserInfoResponse::fromArray($data);
    }

    /**
     * DE: Dekodiert und validiert ID Token.
     *     Signatur-Verifikation wird an JwtVerifier delegiert.
     * EN: Decodes and validates ID token.
     *     Signature verification is delegated to JwtVerifier.
     *
     * @param bool $verifySignature Wenn true, wird die Signatur via JWKS validiert
     * @param bool $validateClaims Wenn true, werden iss, aud, exp, iat validiert
     * @param string|null $expectedNonce Erwarteter Nonce-Wert (optional)
     * @return array<string, mixed>
     * @throws OidcProtocolException
     * @throws ClaimsValidationException
     */
    public function decodeIdToken(
        string $idToken,
        bool $verifySignature = true,
        bool $validateClaims = true,
        ?string $expectedNonce = null,
    ): array {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new OidcProtocolException('Invalid ID token format');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = json_decode($this->base64UrlDecode($headerB64), true);
        $payload = json_decode($this->base64UrlDecode($payloadB64), true);

        if (!is_array($header) || !is_array($payload)) {
            throw new OidcProtocolException('Invalid ID token payload');
        }

        if ($verifySignature) {
            $this->jwtVerifier->verifySignature($headerB64 . '.' . $payloadB64, $signatureB64, $header);
            $this->logger->debug('ID token signature verified');
        }

        if ($validateClaims) {
            $this->validateClaims($payload, $expectedNonce);
            $this->logger->debug('ID token claims validated');
        }

        return $payload;
    }

    /**
     * DE: Validiert die Claims eines ID Tokens.
     * EN: Validates the claims of an ID token.
     *
     * @param array<string, mixed> $claims
     * @throws ClaimsValidationException
     */
    public function validateClaims(array $claims, ?string $expectedNonce = null): void
    {
        $now = time();

        // Validate issuer - accept both internal and public issuer
        $iss = $claims['iss'] ?? null;
        $validIssuers = [$this->config->issuer];
        if ($this->config->publicIssuer !== null) {
            $validIssuers[] = $this->config->publicIssuer;
        }

        if ($iss === null || !in_array($iss, $validIssuers, true)) {
            throw ClaimsValidationException::invalidIssuer(
                expected: implode(' or ', $validIssuers),
                actual: $iss ?? 'null',
            );
        }

        // Validate audience
        $aud = $claims['aud'] ?? null;
        $validAud = is_array($aud)
            ? in_array($this->config->clientId, $aud, true)
            : $aud === $this->config->clientId;

        if (!$validAud) {
            throw ClaimsValidationException::invalidAudience($this->config->clientId, $aud);
        }

        // Validate expiration (with clock skew tolerance)
        $exp = $claims['exp'] ?? null;
        if ($exp !== null && $exp < ($now - self::CLOCK_SKEW_SECONDS)) {
            throw ClaimsValidationException::tokenExpired((int) $exp, $now);
        }

        // Validate issued at (with clock skew tolerance)
        $iat = $claims['iat'] ?? null;
        if ($iat !== null && $iat > ($now + self::CLOCK_SKEW_SECONDS)) {
            throw ClaimsValidationException::tokenNotYetValid((int) $iat, $now);
        }

        // Validate nonce if expected
        if ($expectedNonce !== null) {
            $nonce = $claims['nonce'] ?? null;
            if ($nonce !== $expectedNonce) {
                throw ClaimsValidationException::invalidNonce($expectedNonce, $nonce);
            }
        }
    }

    // =========================================================================
    // Device Authorization Grant (RFC 8628)
    // =========================================================================

    /**
     * DE: Fordert einen Device Code für den Device Authorization Grant an (RFC 8628).
     *     Für Geräte ohne Browser (Smart TV, CLI, IoT).
     * EN: Requests a device code for the device authorization grant (RFC 8628).
     *     For devices without a browser (Smart TV, CLI, IoT).
     *
     * @param list<string> $scopes Die angeforderten Scopes
     * @throws OidcProtocolException wenn kein device_authorization_endpoint konfiguriert ist
     * @throws TokenExchangeFailedException bei Fehlern vom Provider
     *
     * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
     */
    public function requestDeviceCode(array $scopes = ['openid', 'profile', 'email']): DeviceCodeResponse
    {
        if ($this->config->deviceAuthorizationEndpoint === null) {
            throw new OidcProtocolException('No device_authorization_endpoint configured');
        }

        $this->logger->debug('Requesting device code', ['scopes' => $scopes]);

        $params = [
            'client_id' => $this->config->clientId,
            'scope' => implode(' ', $scopes),
        ];

        if ($this->config->clientSecret !== null) {
            $params['client_secret'] = $this->config->clientSecret;
        }

        $response = $this->postForm($this->config->deviceAuthorizationEndpoint, $params);

        if (!isset($response['device_code'], $response['user_code'], $response['verification_uri'])) {
            $error = $response['error'] ?? 'unknown_error';
            $description = $response['error_description'] ?? 'Device authorization request failed';

            $this->logger->error('Device code request failed', [
                'error' => $error,
                'error_description' => $description,
            ]);

            throw new TokenExchangeFailedException($error, $description);
        }

        $this->logger->info('Device code obtained', [
            'user_code' => $response['user_code'],
            'verification_uri' => $response['verification_uri'],
            'expires_in' => $response['expires_in'] ?? 600,
        ]);

        return DeviceCodeResponse::fromArray($response);
    }

    /**
     * DE: Pollt den Token-Endpoint für Device Code Flow (RFC 8628).
     *     Gibt das Ergebnis des Polling-Versuchs zurück.
     * EN: Polls the token endpoint for device code flow (RFC 8628).
     *     Returns the result of the polling attempt.
     *
     * @param string $deviceCode Der Device Code aus requestDeviceCode()
     * @param int $currentInterval Das aktuelle Polling-Intervall in Sekunden
     * @return DeviceCodePollResult Das Ergebnis (success, pending, slow_down, error)
     *
     * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
     * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
     */
    public function pollDeviceToken(string $deviceCode, int $currentInterval = 5): DeviceCodePollResult
    {
        $this->logger->debug('Polling for device token');

        $params = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code' => $deviceCode,
            'client_id' => $this->config->clientId,
        ];

        if ($this->config->clientSecret !== null) {
            $params['client_secret'] = $this->config->clientSecret;
        }

        $response = $this->postForm($this->config->tokenEndpoint, $params);

        // DE: Erfolg - Token erhalten // EN: Success - token received
        if (isset($response['access_token'])) {
            $this->logger->info('Device token obtained successfully');
            return DeviceCodePollResult::success(TokenResponse::fromArray($response));
        }

        // DE: Fehler auswerten // EN: Evaluate error
        $error = $response['error'] ?? 'unknown_error';
        $description = $response['error_description'] ?? null;

        return match ($error) {
            // DE: Noch ausstehend - weiter polling // EN: Still pending - continue polling
            'authorization_pending' => $this->handleAuthorizationPending(),

            // DE: Zu schnell - Intervall erhöhen // EN: Too fast - increase interval
            'slow_down' => $this->handleSlowDown($currentInterval),

            // DE: User hat abgelehnt // EN: User denied
            'access_denied' => $this->handleAccessDenied($description),

            // DE: Code abgelaufen // EN: Code expired
            'expired_token' => $this->handleExpiredToken($description),

            // DE: Ungültiger Grant - Device Code nicht erkannt oder grant_type nicht unterstützt
            // EN: Invalid grant - device code not recognized or grant_type not supported
            'invalid_grant' => $this->handleInvalidGrant($description),

            // DE: Unbekannter Fehler // EN: Unknown error
            default => $this->handleUnknownError($error, $description),
        };
    }

    /**
     * DE: Führt Device Code Flow komplett durch (Polling-Loop).
     *     Blockiert bis Token erhalten oder Fehler/Timeout.
     * EN: Executes complete device code flow (polling loop).
     *     Blocks until token received or error/timeout.
     *
     * @param DeviceCodeResponse $deviceCode Der Device Code aus requestDeviceCode()
     * @param callable|null $onPoll Callback bei jedem Poll (für Progress-Anzeige)
     *                              Signatur: fn(int $attempt, int $interval): void
     * @return TokenResponse Die erhaltenen Tokens
     * @throws TokenExchangeFailedException bei Fehler oder Timeout
     */
    public function awaitDeviceToken(
        DeviceCodeResponse $deviceCode,
        ?callable $onPoll = null,
    ): TokenResponse {
        $interval = $deviceCode->interval;
        $attempt = 0;
        $maxAttempts = (int) ceil($deviceCode->expiresIn / $interval) + 5; // DE: Sicherheitspuffer // EN: Safety buffer

        while ($attempt < $maxAttempts) {
            $attempt++;

            if ($onPoll !== null) {
                $onPoll($attempt, $interval);
            }

            // DE: Warten vor Poll (außer beim ersten Versuch)
            // EN: Wait before poll (except on first attempt)
            if ($attempt > 1) {
                sleep($interval);
            }

            $result = $this->pollDeviceToken($deviceCode->deviceCode, $interval);

            if ($result->isSuccess() && $result->tokenResponse !== null) {
                return $result->tokenResponse;
            }

            if ($result->isError()) {
                throw new TokenExchangeFailedException(
                    $result->status,
                    $result->errorDescription ?? 'Device authorization failed',
                );
            }

            // DE: Intervall anpassen wenn nötig // EN: Adjust interval if needed
            $interval = $result->getRecommendedInterval($interval);
        }

        throw new TokenExchangeFailedException('timeout', 'Device code polling timed out');
    }

    private function handleAuthorizationPending(): DeviceCodePollResult
    {
        $this->logger->debug('Authorization pending, continue polling');
        return DeviceCodePollResult::pending();
    }

    private function handleSlowDown(int $currentInterval): DeviceCodePollResult
    {
        $this->logger->debug('Slow down requested, increasing interval', [
            'current_interval' => $currentInterval,
            'new_interval' => $currentInterval + 5,
        ]);
        return DeviceCodePollResult::slowDown($currentInterval);
    }

    private function handleAccessDenied(?string $description): DeviceCodePollResult
    {
        $this->logger->warning('Device authorization denied by user');
        return DeviceCodePollResult::accessDenied($description);
    }

    private function handleExpiredToken(?string $description): DeviceCodePollResult
    {
        $this->logger->warning('Device code expired');
        return DeviceCodePollResult::expired($description);
    }

    private function handleInvalidGrant(?string $description): DeviceCodePollResult
    {
        // DE: invalid_grant kann bedeuten:
        //     - Device Code wurde nicht gefunden
        //     - Device Code wurde bereits verwendet
        //     - grant_type wird nicht unterstützt
        // EN: invalid_grant can mean:
        //     - Device code was not found
        //     - Device code was already used
        //     - grant_type is not supported
        $this->logger->error('Invalid grant error during device code polling', [
            'error_description' => $description,
            'hint' => 'Check if the SSO server supports device_code grant type',
        ]);

        return DeviceCodePollResult::error(
            'invalid_grant',
            $description ?? 'Invalid grant: The device code may be invalid, already used, or the grant type is not supported by the server.',
        );
    }

    private function handleUnknownError(string $error, ?string $description): DeviceCodePollResult
    {
        $this->logger->error('Unknown device token error', [
            'error' => $error,
            'error_description' => $description,
        ]);

        return DeviceCodePollResult::error(
            $error,
            $description ?? sprintf('Unknown error: %s', $error),
        );
    }

    // =========================================================================
    // Client Credentials Grant (RFC 6749 Section 4.4)
    // =========================================================================

    /**
     * DE: Holt Access Token via Client Credentials Grant (RFC 6749 §4.4).
     *     Für Machine-to-Machine (M2M) Kommunikation ohne User-Interaktion.
     *     Typische Anwendungsfälle: Cronjobs, Microservices, Backend-Integrationen.
     *
     * EN: Gets access token via client credentials grant (RFC 6749 §4.4).
     *     For machine-to-machine (M2M) communication without user interaction.
     *     Typical use cases: cronjobs, microservices, backend integrations.
     *
     * @param list<string> $scopes Die angeforderten Scopes (optional)
     * @return TokenResponse Access Token (kein id_token, normalerweise kein refresh_token)
     * @throws OidcProtocolException wenn kein client_secret konfiguriert ist
     * @throws TokenExchangeFailedException bei Fehlern vom Provider
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
     */
    public function getClientCredentialsToken(array $scopes = []): TokenResponse
    {
        // DE: Client Credentials erfordert ein Client Secret (confidential client)
        // EN: Client credentials requires a client secret (confidential client)
        if ($this->config->clientSecret === null) {
            throw new OidcProtocolException(
                'Client credentials grant requires a client_secret (confidential client)'
            );
        }

        $this->logger->debug('Requesting client credentials token', ['scopes' => $scopes]);

        $params = [
            'grant_type' => 'client_credentials',
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
        ];

        if ($scopes !== []) {
            $params['scope'] = implode(' ', $scopes);
        }

        $response = $this->postForm($this->config->tokenEndpoint, $params);

        if (!isset($response['access_token'])) {
            $error = $response['error'] ?? 'unknown_error';
            $description = $response['error_description'] ?? 'Client credentials token request failed';

            $this->logger->error('Client credentials token request failed', [
                'error' => $error,
                'error_description' => $description,
            ]);

            throw new TokenExchangeFailedException($error, $description);
        }

        $this->logger->info('Client credentials token obtained', [
            'expires_in' => $response['expires_in'] ?? 'unknown',
            'scope' => $response['scope'] ?? 'none',
        ]);

        return TokenResponse::fromArray($response);
    }

    // =========================================================================
    // Token Introspection (RFC 7662)
    // =========================================================================

    /**
     * DE: Validiert ein Token via Introspection Endpoint (RFC 7662).
     *     Für Resource Server (APIs), die eingehende Bearer Tokens prüfen müssen.
     *     Der SSO-Server prüft das Token und gibt Metadaten zurück.
     *
     * EN: Validates a token via introspection endpoint (RFC 7662).
     *     For resource servers (APIs) that need to validate incoming bearer tokens.
     *     The SSO server validates the token and returns metadata.
     *
     * @param string $token Das zu prüfende Token (access_token oder refresh_token)
     * @param string|null $tokenTypeHint Optional: "access_token" oder "refresh_token"
     * @return IntrospectionResponse Token-Metadaten (active, scope, client_id, exp, etc.)
     * @throws OidcProtocolException wenn kein introspection_endpoint konfiguriert
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7662
     */
    public function introspectToken(string $token, ?string $tokenTypeHint = null): IntrospectionResponse
    {
        if ($this->config->introspectionEndpoint === null) {
            throw new OidcProtocolException('No introspection_endpoint configured');
        }

        $this->logger->debug('Introspecting token', [
            'token_type_hint' => $tokenTypeHint,
            'token_length' => strlen($token),
        ]);

        $params = [
            'token' => $token,
            'client_id' => $this->config->clientId,
        ];

        // DE: Client-Authentifizierung (wenn Secret vorhanden)
        // EN: Client authentication (if secret available)
        if ($this->config->clientSecret !== null) {
            $params['client_secret'] = $this->config->clientSecret;
        }

        // DE: Token-Type-Hint hilft dem Server, das Token schneller zu finden
        // EN: Token type hint helps the server find the token faster
        if ($tokenTypeHint !== null) {
            $params['token_type_hint'] = $tokenTypeHint;
        }

        $response = $this->postForm($this->config->introspectionEndpoint, $params);

        // DE: RFC 7662: Response muss immer "active" enthalten
        // EN: RFC 7662: Response must always contain "active"
        if (!isset($response['active'])) {
            $this->logger->warning('Introspection response missing "active" field, treating as inactive');
            return IntrospectionResponse::inactive();
        }

        $introspection = IntrospectionResponse::fromArray($response);

        $this->logger->debug('Token introspection complete', [
            'active' => $introspection->active,
            'client_id' => $introspection->clientId,
            'scope' => $introspection->scope,
        ]);

        return $introspection;
    }

    // =========================================================================
    // Private Helper Methods
    // =========================================================================

    /**
     * @param array<string, string> $params
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
        $bytes = max(1, intdiv($length, 2));
        return bin2hex(random_bytes($bytes));
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

    /**
     * DE: Dekodiert Base64URL-kodierten String.
     * EN: Decodes Base64URL-encoded string.
     *
     * @throws OidcProtocolException wenn Dekodierung fehlschlägt
     */
    private function base64UrlDecode(string $input): string
    {
        if ($input === '') {
            throw new OidcProtocolException('Base64URL decode failed: empty input');
        }

        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($input, '-_', '+/'), true);

        if ($decoded === false) {
            throw new OidcProtocolException('Base64URL decode failed: invalid encoding');
        }

        return $decoded;
    }
}
