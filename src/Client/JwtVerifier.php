<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Client;

use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * DE: Verifiziert JWT-Signaturen gegen JWKS vom Identity Provider.
 *     Framework-unabhängig, nutzt nur PSR-Interfaces.
 * EN: Verifies JWT signatures against JWKS from the identity provider.
 *     Framework-agnostic, uses only PSR interfaces.
 */
final class JwtVerifier
{
    private const SUPPORTED_ALGORITHM = 'RS256';
    private const DEFAULT_CACHE_TTL = 600; // DE: 10 Minuten // EN: 10 minutes
    private const MAX_CACHE_TTL = 30 * 24 * 3600; // DE: 30 Tage Obergrenze // EN: 30 days upper bound

    private LoggerInterface $logger;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        ?LoggerInterface $logger = null,
        private readonly ?CacheInterface $cache = null,
        private readonly ?string $cacheKey = null,
        private readonly int $cacheTtl = self::DEFAULT_CACHE_TTL,
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
     * DE: Invalidiert den JWKS-Cache (erzwingt erneuten Abruf).
     * EN: Invalidates the JWKS cache (forces re-fetch).
     */
    public function invalidateJwksCache(): void
    {
        if ($this->cache !== null && $this->cacheKey !== null) {
            $this->cache->delete($this->cacheKey);
        }
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
     * DE: Lädt JWKS aus Cache oder vom IdP.
     * EN: Loads JWKS from cache or from IdP.
     *
     * @return array<string, mixed>
     * @throws OidcProtocolException
     */
    private function fetchJwks(): array
    {
        // DE: Mit Symfony-Cache // EN: With Symfony cache
        if ($this->cache !== null && $this->cacheKey !== null) {
            /** @var array<string, mixed> */
            return $this->cache->get($this->cacheKey, function (ItemInterface $item): array {
                [$jwks, $providerTtl] = $this->fetchJwksWithTtl();

                // DE: TTL-Priorität: Provider-Header > konfigurierte TTL, mit Obergrenze
                // EN: TTL priority: provider header > configured TTL, with upper bound
                $ttl = $providerTtl !== null
                    ? min($providerTtl, self::MAX_CACHE_TTL)
                    : $this->cacheTtl;

                $item->expiresAfter($ttl);

                $this->logger->debug('JWKS cache TTL set', [
                    'ttl' => $ttl,
                    'source' => $providerTtl !== null ? 'provider' : 'config',
                ]);

                return $jwks;
            });
        }

        // DE: Ohne Cache (Fallback für Tests oder einfache Nutzung)
        // EN: Without cache (fallback for tests or simple usage)
        return $this->doFetchJwks();
    }

    /**
     * DE: Führt den HTTP-Request für JWKS durch.
     * EN: Performs the HTTP request for JWKS.
     *
     * @return array<string, mixed>
     * @throws OidcProtocolException
     */
    private function doFetchJwks(): array
    {
        [$jwks] = $this->fetchJwksWithTtl();

        return $jwks;
    }

    /**
     * DE: Führt den HTTP-Request für JWKS durch und extrahiert die TTL aus Provider-Headern.
     * EN: Performs the HTTP request for JWKS and extracts TTL from provider headers.
     *
     * @return array{0: array<string, mixed>, 1: int|null}
     * @throws OidcProtocolException
     */
    private function fetchJwksWithTtl(): array
    {
        $this->logger->debug('Fetching JWKS from IdP', ['uri' => $this->jwksUri]);

        $request = $this->requestFactory->createRequest('GET', $this->jwksUri)
            ->withHeader('Accept', 'application/json');

        $response = $this->httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new OidcProtocolException(sprintf('JWKS request failed: %d', $response->getStatusCode()));
        }

        // DE: Cache-TTL aus Provider-Headern extrahieren (inspiriert von Symfony 7.4 OidcTokenHandler)
        // EN: Extract cache TTL from provider headers (inspired by Symfony 7.4 OidcTokenHandler)
        $providerTtl = $this->extractTtlFromHeaders($response);

        $data = json_decode((string) $response->getBody(), true);

        if (!is_array($data) || !isset($data['keys'])) {
            throw new OidcProtocolException('Invalid JWKS response');
        }

        $this->logger->info('JWKS fetched successfully', ['keys_count' => count($data['keys'])]);

        return [$data, $providerTtl];
    }

    /**
     * DE: Extrahiert Cache-TTL aus HTTP-Response-Headern (Cache-Control: max-age oder Expires).
     * EN: Extracts cache TTL from HTTP response headers (Cache-Control: max-age or Expires).
     */
    private function extractTtlFromHeaders(\Psr\Http\Message\ResponseInterface $response): ?int
    {
        // DE: Priorität 1: Cache-Control: max-age=N
        // EN: Priority 1: Cache-Control: max-age=N
        $cacheControl = $response->getHeaderLine('Cache-Control');
        if ($cacheControl !== '' && preg_match('/max-age=(\d+)/', $cacheControl, $matches)) {
            $maxAge = (int) $matches[1];
            if ($maxAge > 0) {
                return $maxAge;
            }
        }

        // DE: Priorität 2: Expires Header als Fallback
        // EN: Priority 2: Expires header as fallback
        $expires = $response->getHeaderLine('Expires');
        if ($expires !== '') {
            $expiresTimestamp = strtotime($expires);
            if ($expiresTimestamp !== false) {
                $ttl = $expiresTimestamp - time();
                if ($ttl > 0) {
                    return $ttl;
                }
            }
        }

        return null;
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
            /** @var int<0, 127> $length */
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), "\x00");
        $octetCount = strlen($temp);

        // DE: 0x80 | strlen($temp) ergibt Werte 0x81-0x84 (max 4 Oktetts für 32-bit)
        // EN: 0x80 | strlen($temp) yields values 0x81-0x84 (max 4 octets for 32-bit)
        /** @var int<129, 132> $lengthOctet */
        $lengthOctet = 0x80 | $octetCount;

        return chr($lengthOctet) . $temp;
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
