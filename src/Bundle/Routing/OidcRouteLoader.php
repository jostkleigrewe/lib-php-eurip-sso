<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Routing;

use Jostkleigrewe\Sso\Bundle\Controller\AuthenticationController;
use Jostkleigrewe\Sso\Bundle\Controller\BackchannelLogoutController;
use Jostkleigrewe\Sso\Bundle\Controller\DiagnosticsController;
use Jostkleigrewe\Sso\Bundle\Controller\FrontchannelLogoutController;
use Jostkleigrewe\Sso\Bundle\Controller\ProfileController;
use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * DE: Lädt OIDC-Routen dynamisch aus der Bundle-Konfiguration.
 * EN: Dynamically loads OIDC routes from bundle configuration.
 *
 * Routes: eurip_sso_login, eurip_sso_callback, eurip_sso_logout,
 *         eurip_sso_backchannel_logout (opt), eurip_sso_frontchannel_logout (opt),
 *         eurip_sso_profile (opt), eurip_sso_debug (opt), eurip_sso_test (opt)
 */
final class OidcRouteLoader extends Loader
{
    private bool $isLoaded = false;

    /**
     * @param array{profile: string|null, debug: string|null, test: string|null, backchannel_logout: string|null, frontchannel_logout: string|null} $optionalRoutes
     */
    public function __construct(
        private readonly string $loginPath,
        private readonly string $callbackPath,
        private readonly string $logoutPath,
        private readonly array $optionalRoutes = [
            'profile' => null,
            'debug' => null,
            'test' => null,
            'backchannel_logout' => null,
            'frontchannel_logout' => null,
        ],
        ?string $env = null,
    ) {
        parent::__construct($env);
    }

    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        if ($this->isLoaded) {
            throw new \RuntimeException('OidcRouteLoader already loaded.');
        }

        $routes = new RouteCollection();

        // Core Routes - Authentication (immer aktiv)
        $routes->add(OidcConstants::ROUTE_LOGIN, new Route(
            path: $this->loginPath,
            defaults: ['_controller' => AuthenticationController::class . '::login'],
            methods: ['GET'],
        ));

        $routes->add(OidcConstants::ROUTE_CALLBACK, new Route(
            path: $this->callbackPath,
            defaults: ['_controller' => AuthenticationController::class . '::callback'],
            methods: ['GET'],
        ));

        $routes->add(OidcConstants::ROUTE_LOGOUT, new Route(
            path: $this->logoutPath,
            defaults: ['_controller' => AuthenticationController::class . '::logout'],
            methods: ['GET'],
        ));

        // Optional Routes - Profile
        if (($this->optionalRoutes['profile'] ?? null) !== null) {
            $routes->add(OidcConstants::ROUTE_PROFILE, new Route(
                path: $this->optionalRoutes['profile'],
                defaults: ['_controller' => ProfileController::class . '::profile'],
                methods: ['GET'],
            ));
        }

        // Optional Routes - Diagnostics
        if (($this->optionalRoutes['debug'] ?? null) !== null) {
            $routes->add(OidcConstants::ROUTE_DEBUG, new Route(
                path: $this->optionalRoutes['debug'],
                defaults: ['_controller' => DiagnosticsController::class . '::debug'],
                methods: ['GET'],
            ));
        }

        if (($this->optionalRoutes['test'] ?? null) !== null) {
            $routes->add(OidcConstants::ROUTE_TEST, new Route(
                path: $this->optionalRoutes['test'],
                defaults: ['_controller' => DiagnosticsController::class . '::test'],
                methods: ['GET'],
            ));
        }

        // Optional Routes - Back-Channel Logout (OpenID Connect Back-Channel Logout 1.0)
        if (($this->optionalRoutes['backchannel_logout'] ?? null) !== null) {
            $routes->add(OidcConstants::ROUTE_BACKCHANNEL_LOGOUT, new Route(
                path: $this->optionalRoutes['backchannel_logout'],
                defaults: ['_controller' => BackchannelLogoutController::class . '::backchannelLogout'],
                methods: ['POST'],
            ));
        }

        // Optional Routes - Front-Channel Logout (OpenID Connect Front-Channel Logout 1.0)
        if (($this->optionalRoutes['frontchannel_logout'] ?? null) !== null) {
            $routes->add(OidcConstants::ROUTE_FRONTCHANNEL_LOGOUT, new Route(
                path: $this->optionalRoutes['frontchannel_logout'],
                defaults: ['_controller' => FrontchannelLogoutController::class . '::frontchannelLogout'],
                methods: ['GET'],
            ));
        }

        $this->isLoaded = true;

        return $routes;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === 'eurip_sso';
    }
}
