<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Client;

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
    private const JWKS_CACHE_TTL_SECONDS = 600; // DE: 10 Minuten (schnellere Key-Rotation) // EN: 10 minutes (faster key rotation)
    private const SUPPORTED_ALGORITHM = 'RS256';

    /** @var array<string, mixed>|null */
    private ?array $jwksCache = null;

    private ?int $jwksCacheTimestamp = null;

    private LoggerInterface $logger;

    public function __construct(
        private readonly OidcClientConfig $config,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
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
     * EN: Decodes and validates ID token.
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
            $this->verifySignature($headerB64 . '.' . $payloadB64, $signatureB64, $header);
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

    /**
     * DE: Validiert die Signatur eines ID Tokens.
     * EN: Validates the signature of an ID token.
     *
     * @param array<string, mixed> $header
     * @throws OidcProtocolException
     */
    private function verifySignature(string $data, string $signatureB64, array $header): void
    {
        $alg = $header['alg'] ?? null;
        $kid = $header['kid'] ?? null;

        if ($alg !== self::SUPPORTED_ALGORITHM) {
            throw new OidcProtocolException('Unsupported algorithm: ' . ($alg ?? 'none'));
        }

        $jwks = $this->fetchJwks();
        $key = $this->findKey($jwks, $kid);

        if ($key === null) {
            throw new OidcProtocolException('No matching key found in JWKS');
        }

        $publicKey = $this->jwkToPublicKey($key);
        $signature = $this->base64UrlDecode($signatureB64);

        $result = openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        // DE: -1 = Fehler bei Verifikation, 0 = ungültige Signatur, 1 = gültig
        // EN: -1 = verification error, 0 = invalid signature, 1 = valid
        if ($result === -1) {
            throw new OidcProtocolException('Signature verification failed: ' . (openssl_error_string() ?: 'unknown error'));
        }
        if ($result !== 1) {
            throw new OidcProtocolException('Invalid ID token signature');
        }
    }

    /**
     * DE: Lädt JWKS vorab (für Cache-Warmup).
     * EN: Preloads JWKS data (for cache warmup).
     *
     * @param array<string, mixed> $jwks
     */
    public function preloadJwks(array $jwks): void
    {
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new \InvalidArgumentException('Invalid JWKS format: missing keys array');
        }
        $this->jwksCache = $jwks;
        $this->jwksCacheTimestamp = time();
        $this->logger->debug('JWKS preloaded', ['keys_count' => count($jwks['keys'])]);
    }

    /**
     * DE: Ruft JWKS ab und gibt sie zurück (für Cache-Warmup).
     * EN: Fetches JWKS and returns it (for cache warmup).
     *
     * @return array<string, mixed>
     * @throws OidcProtocolException
     */
    public function fetchAndCacheJwks(): array
    {
        return $this->fetchJwks();
    }

    /**
     * DE: Prüft ob JWKS bereits geladen sind.
     * EN: Checks if JWKS are already loaded.
     */
    public function hasJwksLoaded(): bool
    {
        return $this->jwksCache !== null;
    }

    /**
     * DE: Invalidiert den JWKS-Cache (erzwingt erneuten Abruf).
     * EN: Invalidates the JWKS cache (forces re-fetch).
     */
    public function invalidateJwksCache(): void
    {
        $this->jwksCache = null;
        $this->jwksCacheTimestamp = null;
        $this->logger->debug('JWKS cache invalidated');
    }

    /**
     * @return array<string, mixed>
     * @throws OidcProtocolException
     */
    private function fetchJwks(): array
    {
        // DE: Cache-Invalidierung nach TTL // EN: Cache invalidation after TTL
        if ($this->jwksCache !== null && $this->jwksCacheTimestamp !== null) {
            if (time() > $this->jwksCacheTimestamp + self::JWKS_CACHE_TTL_SECONDS) {
                $this->logger->debug('JWKS cache expired, refetching');
                $this->jwksCache = null;
                $this->jwksCacheTimestamp = null;
            } else {
                return $this->jwksCache;
            }
        }

        if ($this->jwksCache !== null) {
            return $this->jwksCache;
        }

        $this->logger->debug('Fetching JWKS', ['uri' => $this->config->jwksUri]);

        $request = $this->requestFactory->createRequest('GET', $this->config->jwksUri)
            ->withHeader('Accept', 'application/json');

        $response = $this->httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new OidcProtocolException('JWKS request failed: ' . $response->getStatusCode());
        }

        $data = json_decode((string) $response->getBody(), true);

        if (!is_array($data) || !isset($data['keys'])) {
            throw new OidcProtocolException('Invalid JWKS response');
        }

        $this->jwksCache = $data;
        $this->jwksCacheTimestamp = time();

        return $data;
    }

    /**
     * DE: Sucht einen passenden Key aus dem JWKS (PHP 8.4 array_find).
     * EN: Finds a matching key from the JWKS (PHP 8.4 array_find).
     *
     * @param array<string, mixed> $jwks
     * @return array<string, mixed>|null
     */
    private function findKey(array $jwks, ?string $kid): ?array
    {
        return array_find(
            $jwks['keys'],
            fn (array $key): bool =>
                ($kid === null || ($key['kid'] ?? null) === $kid)
                && ($key['use'] ?? 'sig') === 'sig'
                && ($key['kty'] ?? null) === 'RSA',
        );
    }

    /**
     * @param array<string, mixed> $jwk
     * @throws OidcProtocolException
     */
    private function jwkToPublicKey(array $jwk): \OpenSSLAsymmetricKey
    {
        if (!isset($jwk['n'], $jwk['e'])) {
            throw new OidcProtocolException('Invalid JWK: missing n or e');
        }

        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);

        // Build DER-encoded RSA public key
        $modulus = $this->encodeInteger($n);
        $exponent = $this->encodeInteger($e);

        $rsaPublicKey = "\x30" . $this->encodeLength(strlen($modulus) + strlen($exponent)) . $modulus . $exponent;
        $algorithmIdentifier = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $bitString = "\x03" . $this->encodeLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $der = "\x30" . $this->encodeLength(strlen($algorithmIdentifier) + strlen($bitString)) . $algorithmIdentifier . $bitString;

        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----";

        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            throw new OidcProtocolException('Failed to parse public key from JWK');
        }

        return $key;
    }

    private function encodeInteger(string $data): string
    {
        // Add leading zero if high bit is set (to ensure positive integer)
        if (ord($data[0]) > 0x7f) {
            $data = "\x00" . $data;
        }

        return "\x02" . $this->encodeLength(strlen($data)) . $data;
    }

    private function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($temp)) . $temp;
    }

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
