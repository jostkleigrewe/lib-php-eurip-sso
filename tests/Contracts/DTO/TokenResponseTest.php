<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Tests\Contracts\DTO;

use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * DE: Tests für TokenResponse - Expiration Handling.
 * EN: Tests for TokenResponse - expiration handling.
 */
final class TokenResponseTest extends TestCase
{
    #[Test]
    public function isExpiredReturnsFalseForValidToken(): void
    {
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: 'id-token',
            refreshToken: 'refresh-token',
            expiresIn: 3600,
            tokenType: 'Bearer',
        );

        $this->assertFalse($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsTrueForExpiredToken(): void
    {
        $pastTime = new \DateTimeImmutable('-1 hour');
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: null,
            expiresIn: 60,
            tokenType: 'Bearer',
            createdAt: $pastTime,
        );

        $this->assertTrue($token->isExpired());
    }

    #[Test]
    public function isExpiringSoonReturnsTrueWithinBuffer(): void
    {
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: null,
            expiresIn: 30, // Expires in 30 seconds
            tokenType: 'Bearer',
        );

        // With default 60s buffer, 30s expiry should return true
        $this->assertTrue($token->isExpiringSoon(60));
        // With 10s buffer, 30s expiry should return false
        $this->assertFalse($token->isExpiringSoon(10));
    }

    #[Test]
    public function getRemainingSecondsReturnsCorrectValue(): void
    {
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: null,
            expiresIn: 3600,
            tokenType: 'Bearer',
        );

        $remaining = $token->getRemainingSeconds();

        // Should be close to 3600 (allow 5 seconds tolerance for test execution)
        $this->assertGreaterThan(3595, $remaining);
        $this->assertLessThanOrEqual(3600, $remaining);
    }

    #[Test]
    public function getRemainingSecondsReturnsZeroForExpiredToken(): void
    {
        $pastTime = new \DateTimeImmutable('-1 hour');
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: null,
            expiresIn: 60,
            tokenType: 'Bearer',
            createdAt: $pastTime,
        );

        $this->assertEquals(0, $token->getRemainingSeconds());
    }

    #[Test]
    public function canRefreshReturnsTrueWithRefreshToken(): void
    {
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: 'refresh-token',
            expiresIn: 3600,
            tokenType: 'Bearer',
        );

        $this->assertTrue($token->canRefresh());
    }

    #[Test]
    public function canRefreshReturnsFalseWithoutRefreshToken(): void
    {
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: null,
            expiresIn: 3600,
            tokenType: 'Bearer',
        );

        $this->assertFalse($token->canRefresh());
    }

    #[Test]
    public function expiresAtIsCalculatedCorrectly(): void
    {
        $now = new \DateTimeImmutable();
        $token = new TokenResponse(
            accessToken: 'access-token',
            idToken: null,
            refreshToken: null,
            expiresIn: 3600,
            tokenType: 'Bearer',
            createdAt: $now,
        );

        $expected = $now->modify('+3600 seconds');

        $this->assertEquals(
            $expected->getTimestamp(),
            $token->expiresAt->getTimestamp()
        );
    }
}
