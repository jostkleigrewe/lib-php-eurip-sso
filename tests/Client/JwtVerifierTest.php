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

/**
 * DE: Tests für JwtVerifier mit echtem RSA-Key-Pair.
 * EN: Tests for JwtVerifier with real RSA key pair.
 */
final class JwtVerifierTest extends TestCase
{
    private const KID = 'test-key-1';
    private const JWKS_URI = 'https://sso.example.com/.well-known/jwks.json';

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
        $verifier = $this->createVerifierWithPreloadedJwks();
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        // DE: Darf keine Exception werfen
        // EN: Must not throw an exception
        $verifier->verifySignature($data, $signatureB64, $header);

        $this->assertTrue(true);
    }

    #[Test]
    public function verifySignatureSucceedsWithoutKidWhenSingleKey(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256']);

        $verifier->verifySignature($data, $signatureB64, $header);

        $this->assertTrue(true);
    }

    // ── Invalid Signature ────────────────────────────────────────────

    #[Test]
    public function verifySignatureThrowsOnWrongSignature(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();
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
        $verifier = $this->createVerifierWithPreloadedJwks();
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
        // DE: HTTP-Mock gibt JWKS ohne den gesuchten kid zurück (auch beim Retry)
        // EN: HTTP mock returns JWKS without the requested kid (even on retry)
        $verifier = $this->createVerifierWithHttpMock($this->buildJwks());
        $verifier->preloadJwks($this->buildJwks());

        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => 'unknown-kid']);

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('No matching key found in JWKS');

        $verifier->verifySignature($data, $signatureB64, $header);
    }

    // ── Unsupported Algorithm ────────────────────────────────────────

    #[Test]
    public function verifySignatureThrowsOnUnsupportedAlgorithm(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Unsupported algorithm: HS256');

        $verifier->verifySignature('header.payload', 'signature', ['alg' => 'HS256']);
    }

    #[Test]
    public function verifySignatureThrowsOnMissingAlgorithm(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Unsupported algorithm: none');

        $verifier->verifySignature('header.payload', 'signature', []);
    }

    // ── Key Rotation Retry ───────────────────────────────────────────

    #[Test]
    public function verifySignatureRetriesOnKeyRotation(): void
    {
        // DE: Preloaded JWKS hat nur den alten Key (kid='old-key')
        // EN: Preloaded JWKS only has the old key (kid='old-key')
        $oldJwk = $this->jwk;
        $oldJwk['kid'] = 'old-key';
        $oldJwks = ['keys' => [$oldJwk]];

        // DE: HTTP-Mock gibt neue JWKS mit dem richtigen Key zurück
        // EN: HTTP mock returns new JWKS with the correct key
        $newJwks = $this->buildJwks();
        $verifier = $this->createVerifierWithHttpMock($newJwks);
        $verifier->preloadJwks($oldJwks);

        // DE: JWT signiert mit kid='test-key-1' (nicht im preloaded Cache)
        // EN: JWT signed with kid='test-key-1' (not in preloaded cache)
        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        // DE: Erster Versuch: kid nicht gefunden → Cache invalidieren → HTTP-Fetch → kid gefunden → ok
        // EN: First attempt: kid not found → invalidate cache → HTTP fetch → kid found → ok
        $verifier->verifySignature($data, $signatureB64, $header);

        $this->assertTrue(true);
    }

    #[Test]
    public function verifySignatureFailsAfterRetryWhenKeyStillNotFound(): void
    {
        // DE: Preloaded und HTTP-JWKS haben nur 'old-key'
        // EN: Preloaded and HTTP JWKS only have 'old-key'
        $oldJwk = $this->jwk;
        $oldJwk['kid'] = 'old-key';
        $oldJwks = ['keys' => [$oldJwk]];

        $verifier = $this->createVerifierWithHttpMock($oldJwks);
        $verifier->preloadJwks($oldJwks);

        [$data, $signatureB64, $header] = $this->signData(['alg' => 'RS256', 'kid' => self::KID]);

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('No matching key found in JWKS');

        $verifier->verifySignature($data, $signatureB64, $header);
    }

    // ── JWKS Cache TTL ───────────────────────────────────────────────

    #[Test]
    public function fetchJwksRefetchesAfterCacheTtlExpired(): void
    {
        // DE: Verifier mit HTTP-Mock erstellen und JWKS preloaden
        // EN: Create verifier with HTTP mock and preload JWKS
        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createMockRequestFactory();

        $verifier = new JwtVerifier(self::JWKS_URI, $httpClient, $requestFactory);
        $verifier->preloadJwks($this->buildJwks());

        // DE: Cache-Timestamp auf abgelaufen setzen (> 600 Sekunden her)
        // EN: Set cache timestamp to expired (> 600 seconds ago)
        $reflection = new \ReflectionClass($verifier);
        $timestampProp = $reflection->getProperty('jwksCacheTimestamp');
        $timestampProp->setValue($verifier, time() - 601);

        // DE: HTTP-Client gibt frische JWKS zurück
        // EN: HTTP client returns fresh JWKS
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $body = $this->createStub(StreamInterface::class);
        $body->method('__toString')->willReturn(json_encode($this->buildJwks()));
        $response->method('getBody')->willReturn($body);
        $httpClient->method('sendRequest')->willReturn($response);

        // DE: fetchAndCacheJwks() sollte über HTTP neu laden (nicht aus Cache)
        // EN: fetchAndCacheJwks() should refetch via HTTP (not from cache)
        $jwks = $verifier->fetchAndCacheJwks();

        $this->assertArrayHasKey('keys', $jwks);
        $this->assertCount(1, $jwks['keys']);
    }

    #[Test]
    public function fetchJwksUsesCacheBeforeTtlExpired(): void
    {
        // DE: HTTP-Client sollte NICHT aufgerufen werden
        // EN: HTTP client should NOT be called
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->never())->method('sendRequest');

        $requestFactory = $this->createStub(RequestFactoryInterface::class);

        $verifier = new JwtVerifier(self::JWKS_URI, $httpClient, $requestFactory);
        $verifier->preloadJwks($this->buildJwks());

        // DE: Cache ist frisch → kein HTTP-Request
        // EN: Cache is fresh → no HTTP request
        $jwks = $verifier->fetchAndCacheJwks();

        $this->assertArrayHasKey('keys', $jwks);
    }

    // ── Preload + State ──────────────────────────────────────────────

    #[Test]
    public function preloadJwksThrowsOnInvalidFormat(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWKS format');

        $verifier->preloadJwks(['invalid' => 'data']);
    }

    #[Test]
    public function hasJwksLoadedReturnsFalseInitially(): void
    {
        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createStub(RequestFactoryInterface::class);

        $verifier = new JwtVerifier(self::JWKS_URI, $httpClient, $requestFactory);

        $this->assertFalse($verifier->hasJwksLoaded());
    }

    #[Test]
    public function hasJwksLoadedReturnsTrueAfterPreload(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();

        $this->assertTrue($verifier->hasJwksLoaded());
    }

    #[Test]
    public function invalidateJwksCacheClearsCache(): void
    {
        $verifier = $this->createVerifierWithPreloadedJwks();

        $this->assertTrue($verifier->hasJwksLoaded());
        $verifier->invalidateJwksCache();
        $this->assertFalse($verifier->hasJwksLoaded());
    }

    // ── Helper Methods ───────────────────────────────────────────────

    /**
     * @return array<string, mixed>
     */
    private function buildJwks(?array $keys = null): array
    {
        return ['keys' => $keys ?? [$this->jwk]];
    }

    private function createVerifierWithPreloadedJwks(): JwtVerifier
    {
        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createStub(RequestFactoryInterface::class);

        $verifier = new JwtVerifier(self::JWKS_URI, $httpClient, $requestFactory);
        $verifier->preloadJwks($this->buildJwks());

        return $verifier;
    }

    /**
     * DE: Erstellt einen JwtVerifier mit HTTP-Mock der die gegebenen JWKS zurückgibt.
     * EN: Creates a JwtVerifier with HTTP mock that returns the given JWKS.
     */
    private function createVerifierWithHttpMock(array $jwks): JwtVerifier
    {
        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createMockRequestFactory();

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $body = $this->createStub(StreamInterface::class);
        $body->method('__toString')->willReturn(json_encode($jwks));
        $response->method('getBody')->willReturn($body);
        $httpClient->method('sendRequest')->willReturn($response);

        return new JwtVerifier(self::JWKS_URI, $httpClient, $requestFactory);
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
