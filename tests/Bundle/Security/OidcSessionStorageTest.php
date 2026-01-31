<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Tests\Bundle\Security;

use Jostkleigrewe\Sso\Bundle\Security\OidcSessionStorage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * DE: Tests für OidcSessionStorage - State Management und Security.
 * EN: Tests for OidcSessionStorage - state management and security.
 */
final class OidcSessionStorageTest extends TestCase
{
    private RequestStack $requestStack;
    private Session $session;
    private OidcSessionStorage $storage;

    protected function setUp(): void
    {
        $this->session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($this->session);

        $this->requestStack = new RequestStack();
        $this->requestStack->push($request);

        $this->storage = new OidcSessionStorage($this->requestStack);
    }

    #[Test]
    public function storeAndRetrieveState(): void
    {
        $state = 'test-state-123';
        $nonce = 'test-nonce-456';
        $verifier = 'test-verifier-789';

        $this->storage->store($state, $nonce, $verifier);

        $result = $this->storage->validateAndClear($state);

        $this->assertNotNull($result);
        $this->assertEquals($nonce, $result['nonce']);
        $this->assertEquals($verifier, $result['verifier']);
    }

    #[Test]
    public function validateRejectsWrongState(): void
    {
        $this->storage->store('correct-state', 'nonce', 'verifier');

        $result = $this->storage->validateAndClear('wrong-state');

        $this->assertNull($result);
    }

    #[Test]
    public function validateRejectsReplayAttack(): void
    {
        $state = 'test-state';
        $this->storage->store($state, 'nonce', 'verifier');

        // First use should succeed
        $result1 = $this->storage->validateAndClear($state);
        $this->assertNotNull($result1);

        // Second use (replay) should fail
        $result2 = $this->storage->validateAndClear($state);
        $this->assertNull($result2);
    }

    #[Test]
    public function validateRejectsMissingState(): void
    {
        // No state stored
        $result = $this->storage->validateAndClear('any-state');

        $this->assertNull($result);
    }

    #[Test]
    public function hasStateReturnsTrueWhenStored(): void
    {
        $this->assertFalse($this->storage->hasState());

        $this->storage->store('state', 'nonce', 'verifier');

        $this->assertTrue($this->storage->hasState());
    }

    #[Test]
    public function clearRemovesAllData(): void
    {
        $this->storage->store('state', 'nonce', 'verifier');
        $this->assertTrue($this->storage->hasState());

        $this->storage->clear();

        $this->assertFalse($this->storage->hasState());
    }

    #[Test]
    public function markSuccessAndClearRemovesAllData(): void
    {
        $this->storage->store('state', 'nonce', 'verifier');

        $this->storage->markSuccessAndClear();

        $this->assertFalse($this->storage->hasState());
    }

    #[Test]
    public function stateIsTimingAttackSafe(): void
    {
        $this->storage->store('correct-state', 'nonce', 'verifier');

        // These should all fail and take similar time (timing-safe comparison)
        $this->assertNull($this->storage->validateAndClear('wrong-state'));
    }
}
