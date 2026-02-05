<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Tests\Bundle\Twig;

use Jostkleigrewe\Sso\Bundle\Twig\EuripSsoTwigExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Twig\Extension\AbstractExtension;

/**
 * DE: Tests für EuripSsoTwigExtension.
 *     Prüft die Struktur der Extension und dass alle erwarteten Methoden existieren.
 *     Integration-Tests decken die Funktionalität ab.
 * EN: Tests for EuripSsoTwigExtension.
 *     Tests the structure of the extension and that all expected methods exist.
 *     Integration tests cover the functionality.
 */
final class EuripSsoTwigExtensionTest extends TestCase
{
    #[Test]
    public function extendsAbstractExtension(): void
    {
        $reflection = new ReflectionClass(EuripSsoTwigExtension::class);
        $this->assertTrue($reflection->isSubclassOf(AbstractExtension::class));
    }

    #[Test]
    public function hasFinalModifier(): void
    {
        $reflection = new ReflectionClass(EuripSsoTwigExtension::class);
        $this->assertTrue($reflection->isFinal());
    }

    #[Test]
    public function hasGetFunctionsMethod(): void
    {
        $this->assertTrue(method_exists(EuripSsoTwigExtension::class, 'getFunctions'));

        $reflection = new ReflectionMethod(EuripSsoTwigExtension::class, 'getFunctions');
        $this->assertTrue($reflection->isPublic());
        $this->assertSame('array', $reflection->getReturnType()?->getName());
    }

    #[Test]
    public function hasExpectedPublicMethods(): void
    {
        $expectedMethods = [
            'isAuthenticated',
            'getEmail',
            'getName',
            'getUserId',
            'hasRole',
            'hasPermission',
            'hasGroup',
            'getClaim',
        ];

        foreach ($expectedMethods as $methodName) {
            $this->assertTrue(
                method_exists(EuripSsoTwigExtension::class, $methodName),
                "Method $methodName should exist"
            );

            $reflection = new ReflectionMethod(EuripSsoTwigExtension::class, $methodName);
            $this->assertTrue($reflection->isPublic(), "Method $methodName should be public");
        }
    }

    #[Test]
    public function isAuthenticatedReturnsBool(): void
    {
        $reflection = new ReflectionMethod(EuripSsoTwigExtension::class, 'isAuthenticated');
        $this->assertSame('bool', $reflection->getReturnType()?->getName());
    }

    #[Test]
    public function hasRoleAcceptsStringParameter(): void
    {
        $reflection = new ReflectionMethod(EuripSsoTwigExtension::class, 'hasRole');
        $params = $reflection->getParameters();

        $this->assertCount(1, $params);
        $this->assertSame('role', $params[0]->getName());
        $this->assertSame('string', $params[0]->getType()?->getName());
    }

    #[Test]
    public function getClaimAcceptsNameAndDefault(): void
    {
        $reflection = new ReflectionMethod(EuripSsoTwigExtension::class, 'getClaim');
        $params = $reflection->getParameters();

        $this->assertCount(2, $params);
        $this->assertSame('name', $params[0]->getName());
        $this->assertSame('default', $params[1]->getName());
        $this->assertTrue($params[1]->isDefaultValueAvailable());
        $this->assertNull($params[1]->getDefaultValue());
    }
}
