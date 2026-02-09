<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Tests\Client;

use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

final class OidcClientTest extends TestCase
{
    private OidcClientConfig $config;
    private ClientInterface $httpClient;
    private RequestFactoryInterface $requestFactory;
    private StreamFactoryInterface $streamFactory;
    private JwtVerifier $jwtVerifier;

    protected function setUp(): void
    {
        $this->config = new OidcClientConfig(
            clientId: 'test-client',
            issuer: 'https://sso.example.com',
            authorizationEndpoint: 'https://sso.example.com/authorize',
            tokenEndpoint: 'https://sso.example.com/token',
            jwksUri: 'https://sso.example.com/.well-known/jwks.json',
            redirectUri: 'https://app.example.com/callback',
            userInfoEndpoint: 'https://sso.example.com/userinfo',
            endSessionEndpoint: 'https://sso.example.com/logout',
            clientSecret: null,
            publicIssuer: null,
        );

        $this->httpClient = $this->createMock(ClientInterface::class);
        $this->requestFactory = $this->createMock(RequestFactoryInterface::class);
        $this->streamFactory = $this->createMock(StreamFactoryInterface::class);

        // Setup request factory mock
        $request = $this->createMock(RequestInterface::class);
        $request->method('withHeader')->willReturnSelf();
        $request->method('withBody')->willReturnSelf();
        $this->requestFactory->method('createRequest')->willReturn($request);

        // Setup stream factory mock
        $stream = $this->createMock(StreamInterface::class);
        $this->streamFactory->method('createStream')->willReturn($stream);

        // Setup JwtVerifier
        $this->jwtVerifier = new JwtVerifier(
            'https://sso.example.com/.well-known/jwks.json',
            $this->httpClient,
            $this->requestFactory,
        );
    }

    private function createClient(): OidcClient
    {
        return new OidcClient(
            $this->config,
            $this->httpClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->jwtVerifier,
        );
    }

    #[Test]
    public function buildAuthorizationUrlReturnsValidStructure(): void
    {
        $client = $this->createClient();

        $result = $client->buildAuthorizationUrl(['openid', 'profile']);

        $this->assertArrayHasKey('url', $result);
        $this->assertArrayHasKey('state', $result);
        $this->assertArrayHasKey('nonce', $result);
        $this->assertArrayHasKey('code_verifier', $result);

        $this->assertStringStartsWith('https://sso.example.com/authorize?', $result['url']);
        $this->assertStringContainsString('response_type=code', $result['url']);
        $this->assertStringContainsString('client_id=test-client', $result['url']);
        $this->assertStringContainsString('code_challenge_method=S256', $result['url']);
    }

    #[Test]
    public function buildAuthorizationUrlGeneratesUniqueStateAndNonce(): void
    {
        $client = $this->createClient();

        $result1 = $client->buildAuthorizationUrl();
        $result2 = $client->buildAuthorizationUrl();

        $this->assertNotEquals($result1['state'], $result2['state']);
        $this->assertNotEquals($result1['nonce'], $result2['nonce']);
        $this->assertNotEquals($result1['code_verifier'], $result2['code_verifier']);
    }

    #[Test]
    public function buildLogoutUrlWithoutParams(): void
    {
        $client = $this->createClient();

        $url = $client->buildLogoutUrl();

        $this->assertEquals('https://sso.example.com/logout', $url);
    }

    #[Test]
    public function buildLogoutUrlWithParams(): void
    {
        $client = $this->createClient();

        $url = $client->buildLogoutUrl('https://app.example.com/', 'id_token_hint');

        $this->assertStringStartsWith('https://sso.example.com/logout?', $url);
        $this->assertStringContainsString('post_logout_redirect_uri=', $url);
        $this->assertStringContainsString('id_token_hint=id_token_hint', $url);
    }

    #[Test]
    public function buildLogoutUrlThrowsWhenNoEndSessionEndpoint(): void
    {
        $configWithoutLogout = new OidcClientConfig(
            clientId: 'test-client',
            issuer: 'https://sso.example.com',
            authorizationEndpoint: 'https://sso.example.com/authorize',
            tokenEndpoint: 'https://sso.example.com/token',
            jwksUri: '',
            redirectUri: 'https://app.example.com/callback',
            userInfoEndpoint: '',
            endSessionEndpoint: null,
        );

        $client = new OidcClient(
            $configWithoutLogout,
            $this->httpClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->jwtVerifier,
        );

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('No end_session_endpoint configured');

        $client->buildLogoutUrl();
    }

    #[Test]
    public function validateClaimsPassesWithValidClaims(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'iat' => time() - 60,
            'sub' => 'user123',
        ];

        // Should not throw
        $client->validateClaims($claims);

        $this->assertTrue(true);
    }

    #[Test]
    public function validateClaimsThrowsOnInvalidIssuer(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://evil.example.com',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'sub' => 'user123',
        ];

        $this->expectException(ClaimsValidationException::class);
        $this->expectExceptionMessage('Invalid issuer');

        $client->validateClaims($claims);
    }

    #[Test]
    public function validateClaimsThrowsOnInvalidAudience(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'other-client',
            'exp' => time() + 3600,
            'sub' => 'user123',
        ];

        $this->expectException(ClaimsValidationException::class);
        $this->expectExceptionMessage('Invalid audience');

        $client->validateClaims($claims);
    }

    #[Test]
    public function validateClaimsAcceptsAudienceArray(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => ['other-client', 'test-client'],
            'exp' => time() + 3600,
            'sub' => 'user123',
        ];

        // Should not throw
        $client->validateClaims($claims);

        $this->assertTrue(true);
    }

    #[Test]
    public function validateClaimsThrowsOnExpiredToken(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'exp' => time() - 120, // Expired 2 minutes ago (beyond clock skew)
            'sub' => 'user123',
        ];

        $this->expectException(ClaimsValidationException::class);
        $this->expectExceptionMessage('Token expired');

        $client->validateClaims($claims);
    }

    #[Test]
    public function validateClaimsAllowsClockSkew(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'exp' => time() - 30, // Expired 30 seconds ago (within clock skew)
            'sub' => 'user123',
        ];

        // Should not throw due to clock skew tolerance
        $client->validateClaims($claims);

        $this->assertTrue(true);
    }

    #[Test]
    public function validateClaimsThrowsOnFutureIat(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'iat' => time() + 120, // 2 minutes in the future (beyond clock skew)
            'sub' => 'user123',
        ];

        $this->expectException(ClaimsValidationException::class);
        $this->expectExceptionMessage('Token not yet valid');

        $client->validateClaims($claims);
    }

    #[Test]
    public function validateClaimsThrowsOnInvalidNonce(): void
    {
        $client = $this->createClient();

        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'nonce' => 'wrong-nonce',
            'sub' => 'user123',
        ];

        $this->expectException(ClaimsValidationException::class);
        $this->expectExceptionMessage('Invalid nonce');

        $client->validateClaims($claims, 'expected-nonce');
    }

    #[Test]
    public function validateClaimsAcceptsPublicIssuer(): void
    {
        $configWithPublicIssuer = new OidcClientConfig(
            clientId: 'test-client',
            issuer: 'http://sso-internal',
            authorizationEndpoint: 'https://sso.example.com/authorize',
            tokenEndpoint: 'http://sso-internal/token',
            jwksUri: '',
            redirectUri: 'https://app.example.com/callback',
            userInfoEndpoint: '',
            publicIssuer: 'https://sso.example.com',
        );

        $client = new OidcClient(
            $configWithPublicIssuer,
            $this->httpClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->jwtVerifier,
        );

        // Should accept both internal and public issuer
        $claims = [
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'sub' => 'user123',
        ];

        $client->validateClaims($claims);
        $this->assertTrue(true);
    }

    #[Test]
    public function decodeIdTokenThrowsOnInvalidFormat(): void
    {
        $client = $this->createClient();

        $this->expectException(OidcProtocolException::class);
        $this->expectExceptionMessage('Invalid ID token format');

        $client->decodeIdToken('invalid.token');
    }

    #[Test]
    public function decodeIdTokenDecodesPayload(): void
    {
        $client = $this->createClient();

        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'iss' => 'https://sso.example.com',
            'aud' => 'test-client',
            'sub' => 'user123',
            'exp' => time() + 3600,
        ]));
        $signature = base64_encode('fake-signature');

        $token = str_replace(['+', '/', '='], ['-', '_', ''], "$header.$payload.$signature");

        $claims = $client->decodeIdToken($token, verifySignature: false, validateClaims: false);

        $this->assertEquals('https://sso.example.com', $claims['iss']);
        $this->assertEquals('test-client', $claims['aud']);
        $this->assertEquals('user123', $claims['sub']);
    }

    #[Test]
    public function getConfigReturnsConfig(): void
    {
        $client = $this->createClient();

        $this->assertSame($this->config, $client->getConfig());
    }
}
