<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Client;

use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * DE: Verifiziert JWT-Signaturen gegen JWKS vom Identity Provider.
 *     Framework-unabhängig, nutzt nur PSR-Interfaces.
 * EN: Verifies JWT signatures against JWKS from the identity provider.
 *     Framework-agnostic, uses only PSR interfaces.
 */
final class JwtVerifier
{
    private const JWKS_CACHE_TTL_SECONDS = 600; // DE: 10 Minuten // EN: 10 minutes
    private const SUPPORTED_ALGORITHM = 'RS256';

    /** @var array<string, mixed>|null */
    private ?array $jwksCache = null;

    private ?int $jwksCacheTimestamp = null;

    private LoggerInterface $logger;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * DE: Validiert die Signatur eines JWT.
     *     Bei unbekanntem Key-ID wird der JWKS-Cache invalidiert und 1x erneut versucht
     *     (Key-Rotation-Resilience).
     * EN: Validates the signature of a JWT.
     *     On unknown key ID, the JWKS cache is invalidated and retried once
     *     (key rotation resilience).
     *
     * @param string $data Base64URL-encoded header.payload
     * @param string $signatureB64 Base64URL-encoded signature
     * @param array<string, mixed> $header Decoded JWT header
     * @throws OidcProtocolException
     */
    public function verifySignature(string $data, string $signatureB64, array $header): void
    {
        try {
            $this->doVerifySignature($data, $signatureB64, $header);
        } catch (OidcProtocolException $e) {
            // DE: Bei unbekanntem Key: Cache invalidieren → neu laden → 1x Retry
            // EN: On unknown key: invalidate cache → refetch → retry once
            if (str_contains($e->getMessage(), 'No matching key found')) {
                $this->logger->info('Key not found in JWKS, attempting key rotation recovery');
                $this->invalidateJwksCache();
                $this->doVerifySignature($data, $signatureB64, $header);

                return;
            }

            throw $e;
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
     * EN: Fetches JWKS and returns them (for cache warmup).
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
     * DE: Führt die eigentliche Signatur-Verifikation durch.
     * EN: Performs the actual signature verification.
     *
     * @param array<string, mixed> $header
     * @throws OidcProtocolException
     */
    private function doVerifySignature(string $data, string $signatureB64, array $header): void
    {
        $alg = $header['alg'] ?? null;
        $kid = $header['kid'] ?? null;

        if ($alg !== self::SUPPORTED_ALGORITHM) {
            throw new OidcProtocolException(sprintf('Unsupported algorithm: %s', $alg ?? 'none'));
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
            throw new OidcProtocolException(sprintf(
                'Signature verification failed: %s',
                openssl_error_string() ?: 'unknown error',
            ));
        }

        if ($result !== 1) {
            throw new OidcProtocolException('Invalid ID token signature');
        }
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

        $this->logger->debug('Fetching JWKS', ['uri' => $this->jwksUri]);

        $request = $this->requestFactory->createRequest('GET', $this->jwksUri)
            ->withHeader('Accept', 'application/json');

        $response = $this->httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new OidcProtocolException(sprintf('JWKS request failed: %d', $response->getStatusCode()));
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
     * DE: Konvertiert einen JWK (JSON Web Key) in einen OpenSSL Public Key.
     * EN: Converts a JWK (JSON Web Key) into an OpenSSL public key.
     *
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

        // DE: DER-kodierter RSA Public Key erstellen
        // EN: Build DER-encoded RSA public key
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
        // DE: Führende Null hinzufügen wenn High-Bit gesetzt (positive Integer sicherstellen)
        // EN: Add leading zero if high bit is set (to ensure positive integer)
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
     * DE: Dekodiert Base64URL-kodierten String.
     * EN: Decodes Base64URL-encoded string.
     *
     * @throws OidcProtocolException
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
