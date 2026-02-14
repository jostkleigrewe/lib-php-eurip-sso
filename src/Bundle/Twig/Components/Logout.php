<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Twig\Components;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * DE: Twig-Komponente für sicheren Logout mit CSRF-Schutz.
 *     Rendert ein POST-Formular mit verstecktem CSRF-Token.
 *     Benötigt symfony/ux-twig-component.
 * EN: Twig component for secure logout with CSRF protection.
 *     Renders a POST form with hidden CSRF token.
 *     Requires symfony/ux-twig-component.
 *
 * @example
 * ```twig
 * {# Einfache Verwendung #}
 * <twig:EuripSso:Logout />
 *
 * {# Mit Optionen #}
 * <twig:EuripSso:Logout label="Abmelden" class="btn btn-danger" />
 *
 * {# Als Link gestylt #}
 * <twig:EuripSso:Logout :asLink="true" />
 * ```
 *
 */
#[\Symfony\UX\TwigComponent\Attribute\AsTwigComponent('EuripSso:Logout', template: '@EuripSso/components/Logout.html.twig')] // @phpstan-ignore attribute.notFound (optional dependency: symfony/ux-twig-component)
final class Logout
{
    /**
     * DE: Button/Link-Beschriftung // EN: Button/link label
     */
    public string $label = 'Logout';

    /**
     * DE: CSS-Klassen für den Button/Link // EN: CSS classes for button/link
     */
    public string $class = '';

    /**
     * DE: Als Link statt Button stylen // EN: Style as link instead of button
     */
    public bool $asLink = false;

    /**
     * DE: Optionale Bestätigungsmeldung (JavaScript confirm).
     *     User-Input wird automatisch escaped.
     * EN: Optional confirmation message (JavaScript confirm).
     *     User input is automatically escaped.
     */
    public ?string $confirm = null;

    public function __construct(
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {
    }

    /**
     * DE: Generiert das CSRF-Token für den Logout.
     * EN: Generates the CSRF token for logout.
     *
     * @api
     */
    public function getCsrfToken(): string
    {
        return $this->csrfTokenManager
            ->getToken(OidcConstants::CSRF_LOGOUT_INTENTION)
            ->getValue();
    }

    /**
     * DE: Gibt die Logout-URL zurück.
     * EN: Returns the logout URL.
     *
     * @api
     */
    public function getLogoutUrl(): string
    {
        return $this->urlGenerator->generate(OidcConstants::ROUTE_LOGOUT);
    }
}
