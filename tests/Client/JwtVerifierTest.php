<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Tests\Client;

use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Symfony\Contracts\Cache\CacheInterface;

/**
 * DE: Tests für JwtVerifier mit echtem RSA-Key-Pair.
 * EN: Tests for JwtVerifier with real RSA key pair.
 */
final class JwtVerifierTest extends TestCase
{
    private const KID = 'test-key-1';
    private const JWKS_URI = 'https://sso.example.com/.well-known/jwks.json';
    private const CACHE_KEY = 'eurip_sso.jwks.v1.test';

    private \OpenSSLAsymmetricKey $privateKey;

    /** @var array<string, string> */
    private array $jwk;

    protected function setUp(): void
    {
        // DE: 2048-bit RSA-Key-Pair für Tests generieren
        // EN: Generate 2048-bit RSA key pair for tests
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        \assert($keyPair instanceof \OpenSSLAsymmetricKey);
        $this->privateKey = $keyPair;

        $details = openssl_pkey_get_details($keyPair);
        \assert(is_array($details));

        $this->jwk = [
            'kty' => 'RSA',
            'kid' => self::KID,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64UrlEncode($details['rsa']['n']),
            'e' => self::base64UrlEncode($details['rsa']['e']),
        ];
    }

    // ── Valid Signature ──────────────────────────────────────────────

    #[Test]
    public function verifySignatureSucceedsWithValidRs256Signature(): void
    {
        $verifier = $this->createVerifierWithCachedJwks();
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        // DE: Darf keine Exception werfen
        // EN: Must not throw an exception
        $verifier->verifySignature($data, $signatureB64, $header);

        $this->assertTrue(true);
    }

    #[Test]
    public function verifySignatureSucceedsWithoutKidWhenSingleKey(): void
    {
        $verifier = $this->createVerifierWithCachedJwks();
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256']);

        $verifier->verifySignature($data, $signatureB64, $header);

        $this->assertTrue(true);
    }

    // ── Invalid Signature ────────────────────────────────────────────

    #[Test]
    public function verifySignatureThrowsOnWrongSignature(): void
    {
        $verifier = $this->createVerifierWithCachedJwks();
        [$data, , $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        // DE: Manipulierte Signatur (gültig Base64URL, aber falscher Inhalt)
        // EN: Tampered signature (valid Base64URL, but wrong content)
        $wrongSignature = self::base64UrlEncode(random_bytes(256));

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Invalid ID token signature');

        $verifier->verifySignature($data, $wrongSignature, $header);
    }

    #[Test]
    public function verifySignatureThrowsOnTamperedData(): void
    {
        $verifier = $this->createVerifierWithCachedJwks();
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        // DE: Daten nach Signierung manipuliert
        // EN: Data tampered after signing
        $tamperedData = $data . 'x';

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Invalid ID token signature');

        $verifier->verifySignature($tamperedData, $signatureB64, $header);
    }

    // ── Unknown Key ID ───────────────────────────────────────────────

    #[Test]
    public function verifySignatureThrowsOnUnknownKid(): void
    {
        // DE: Cache gibt JWKS ohne den gesuchten kid zurück (auch beim Retry)
        // EN: Cache returns JWKS without the requested kid (even on retry)
        $verifier = $this->createVerifierWithCachedJwks();

        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => 'unknown-kid']);

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('No matching key found in JWKS');

        $verifier->verifySignature($data, $signatureB64, $header);
    }

    // ── Unsupported Algorithm ────────────────────────────────────────

    #[Test]
    public function verifySignatureThrowsOnUnsupportedAlgorithm(): void
    {
        $verifier = $this->createVerifierWithCachedJwks();

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Unsupported algorithm: HS256');

        $verifier->verifySignature('header.payload', 'signature', ['alg' => 'HS256']);
    }

    #[Test]
    public function verifySignatureThrowsOnMissingAlgorithm(): void
    {
        $verifier = $this->createVerifierWithCachedJwks();

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Unsupported algorithm: none');

        $verifier->verifySignature('header.payload', 'signature', []);
    }

    // ── Key Rotation Retry ───────────────────────────────────────────

    #[Test]
    public function verifySignatureRetriesOnKeyRotation(): void
    {
        // DE: Erster Cache-Abruf gibt alten Key zurück, nach delete() den neuen
        // EN: First cache fetch returns old key, after delete() the new one
        $oldJwk = $this->jwk;
        $oldJwk['kid'] = 'old-key';
        $oldJwks = ['keys' => [$oldJwk]];
        $newJwks = $this->buildJwks();

        $callCount = 0;
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('get')->willReturnCallback(function ($key, $callback) use (&$callCount, $oldJwks, $newJwks) {
            $callCount++;
            // DE: Erster Abruf = alte JWKS, nach Invalidierung = neue JWKS
            // EN: First fetch = old JWKS, after invalidation = new JWKS
            return $callCount === 1 ? $oldJwks : $newJwks;
        });
        $cache->expects($this->once())->method('delete');

        $verifier = new JwtVerifier(
            jwksUri: self::JWKS_URI,
            httpClient: $this->createStub(ClientInterface::class),
            requestFactory: $this->createStub(RequestFactoryInterface::class),
            cache: $cache,
            cacheKey: self::CACHE_KEY,
        );

        // DE: JWT signiert mit kid='test-key-1' (nicht im ersten Cache-Abruf)
        // EN: JWT signed with kid='test-key-1' (not in first cache fetch)
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        // DE: Erster Versuch: kid nicht gefunden → Cache invalidieren → erneuter Abruf → kid gefunden → ok
        // EN: First attempt: kid not found → invalidate cache → refetch → kid found → ok
        $verifier->verifySignature($data, $signatureB64, $header);

        $this->assertTrue(true);
    }

    #[Test]
    public function verifySignatureFailsAfterRetryWhenKeyStillNotFound(): void
    {
        // DE: Cache gibt immer nur 'old-key' zurück
        // EN: Cache always returns only 'old-key'
        $oldJwk = $this->jwk;
        $oldJwk['kid'] = 'old-key';
        $oldJwks = ['keys' => [$oldJwk]];

        $cache = $this->createMock(CacheInterface::class);
        $cache->method('get')->willReturn($oldJwks);

        $verifier = new JwtVerifier(
            jwksUri: self::JWKS_URI,
            httpClient: $this->createStub(ClientInterface::class),
            requestFactory: $this->createStub(RequestFactoryInterface::class),
            cache: $cache,
            cacheKey: self::CACHE_KEY,
        );

        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('No matching key found in JWKS');

        $verifier->verifySignature($data, $signatureB64, $header);
    }

    // ── Cache Integration ───────────────────────────────────────────

    #[Test]
    public function fetchJwksUsesCacheWhenAvailable(): void
    {
        // DE: HTTP-Client sollte NICHT aufgerufen werden
        // EN: HTTP client should NOT be called
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->never())->method('sendRequest');

        $cache = $this->createMock(CacheInterface::class);
        $cache->method('get')->willReturn($this->buildJwks());

        $verifier = new JwtVerifier(
            jwksUri: self::JWKS_URI,
            httpClient: $httpClient,
            requestFactory: $this->createStub(RequestFactoryInterface::class),
            cache: $cache,
            cacheKey: self::CACHE_KEY,
        );

        // DE: Cache ist vorhanden → kein HTTP-Request
        // EN: Cache is available → no HTTP request
        $jwks = $verifier->fetchAndCacheJwks();

        $this->assertArrayHasKey('keys', $jwks);
    }

    #[Test]
    public function fetchJwksFetchesFromHttpWhenNoCache(): void
    {
        // DE: Ohne Cache sollte HTTP-Client aufgerufen werden
        // EN: Without cache, HTTP client should be called
        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createMockRequestFactory();

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $body = $this->createStub(StreamInterface::class);
        $body->method('__toString')->willReturn(json_encode($this->buildJwks()));
        $response->method('getBody')->willReturn($body);
        $httpClient->method('sendRequest')->willReturn($response);

        $verifier = new JwtVerifier(
            jwksUri: self::JWKS_URI,
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            // DE: Kein Cache // EN: No cache
        );

        $jwks = $verifier->fetchAndCacheJwks();

        $this->assertArrayHasKey('keys', $jwks);
        $this->assertCount(1, $jwks['keys']);
    }

    #[Test]
    public function invalidateJwksCacheDeletesFromCache(): void
    {
        $cache = $this->createMock(CacheInterface::class);
        $cache->expects($this->once())->method('delete')->with(self::CACHE_KEY);

        $verifier = new JwtVerifier(
            jwksUri: self::JWKS_URI,
            httpClient: $this->createStub(ClientInterface::class),
            requestFactory: $this->createStub(RequestFactoryInterface::class),
            cache: $cache,
            cacheKey: self::CACHE_KEY,
        );

        $verifier->invalidateJwksCache();
    }

    // ── Helper Methods ───────────────────────────────────────────────

    /**
     * @return array<string, mixed>
     */
    private function buildJwks(?array $keys = null): array
    {
        return ['keys' => $keys ?? [$this->jwk]];
    }

    /**
     * DE: Erstellt einen JwtVerifier mit Cache-Mock der JWKS zurückgibt.
     * EN: Creates a JwtVerifier with cache mock that returns JWKS.
     */
    private function createVerifierWithCachedJwks(): JwtVerifier
    {
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('get')->willReturn($this->buildJwks());

        return new JwtVerifier(
            jwksUri: self::JWKS_URI,
            httpClient: $this->createStub(ClientInterface::class),
            requestFactory: $this->createStub(RequestFactoryInterface::class),
            cache: $cache,
            cacheKey: self::CACHE_KEY,
        );
    }

    private function createMockRequestFactory(): RequestFactoryInterface
    {
        $request = $this->createStub(RequestInterface::class);
        $request->method('withHeader')->willReturnSelf();

        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($request);

        return $requestFactory;
    }

    /**
     * DE: Signiert Test-Daten mit dem RSA-Private-Key.
     * EN: Signs test data with the RSA private key.
     *
     * @param array<string, string> $header JWT header (alg, kid)
     * @return array{0: string, 1: string, 2: array<string, string>} [$data, $signatureB64, $header]
     */
    private function signData(array $header): array
    {
        $headerB64 = self::base64UrlEncode(json_encode($header));
        $payloadB64 = self::base64UrlEncode(json_encode([
            'iss' => 'https://sso.example.com',
            'sub' => 'user-123',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'iat' => time(),
        ]));

        $data = $headerB64 . '.' . $payloadB64;

        openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return [$data, self::base64UrlEncode($signature), $header];
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
