<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Tests\Contracts;

use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClaimsValidationExceptionTest extends TestCase
{
    #[Test]
    public function extendsOidcProtocolException(): void
    {
        $exception = ClaimsValidationException::invalidIssuer('expected', 'actual');

        $this->assertInstanceOf(OidcProtocolException::class, $exception);
    }

    #[Test]
    public function invalidIssuerContainsDetails(): void
    {
        $exception = ClaimsValidationException::invalidIssuer('https://expected.com', 'https://actual.com');

        $this->assertEquals('iss', $exception->claim);
        $this->assertEquals('https://expected.com', $exception->expected);
        $this->assertEquals('https://actual.com', $exception->actual);
        $this->assertStringContainsString('Invalid issuer', $exception->getMessage());
    }

    #[Test]
    public function invalidAudienceContainsDetails(): void
    {
        $exception = ClaimsValidationException::invalidAudience('expected-client', 'actual-client');

        $this->assertEquals('aud', $exception->claim);
        $this->assertEquals('expected-client', $exception->expected);
        $this->assertEquals('actual-client', $exception->actual);
        $this->assertStringContainsString('Invalid audience', $exception->getMessage());
    }

    #[Test]
    public function invalidAudienceHandlesArray(): void
    {
        $exception = ClaimsValidationException::invalidAudience('expected-client', ['client1', 'client2']);

        $this->assertStringContainsString('client1, client2', $exception->getMessage());
    }

    #[Test]
    public function tokenExpiredContainsDetails(): void
    {
        $exp = time() - 100;
        $now = time();
        $exception = ClaimsValidationException::tokenExpired($exp, $now);

        $this->assertEquals('exp', $exception->claim);
        $this->assertStringContainsString('Token expired', $exception->getMessage());
    }

    #[Test]
    public function tokenNotYetValidContainsDetails(): void
    {
        $iat = time() + 100;
        $now = time();
        $exception = ClaimsValidationException::tokenNotYetValid($iat, $now);

        $this->assertEquals('iat', $exception->claim);
        $this->assertStringContainsString('Token not yet valid', $exception->getMessage());
    }

    #[Test]
    public function invalidNonceContainsDetails(): void
    {
        $exception = ClaimsValidationException::invalidNonce('expected-nonce', 'actual-nonce');

        $this->assertEquals('nonce', $exception->claim);
        $this->assertEquals('expected-nonce', $exception->expected);
        $this->assertEquals('actual-nonce', $exception->actual);
        $this->assertStringContainsString('Invalid nonce', $exception->getMessage());
    }

    #[Test]
    public function invalidNonceHandlesNull(): void
    {
        $exception = ClaimsValidationException::invalidNonce('expected-nonce', null);

        $this->assertStringContainsString('null', $exception->getMessage());
    }
}
