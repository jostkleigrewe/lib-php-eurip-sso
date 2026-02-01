<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle;

use Jostkleigrewe\Sso\Bundle\Controller\AuthenticationController;
use Jostkleigrewe\Sso\Bundle\Controller\DiagnosticsController;
use Jostkleigrewe\Sso\Bundle\Controller\ProfileController;
use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;
use Jostkleigrewe\Sso\Bundle\Routing\OidcRouteLoader;
use Jostkleigrewe\Sso\Bundle\Security\DoctrineOidcUserProvider;
use Jostkleigrewe\Sso\Bundle\Security\OidcSessionStorage;
use Jostkleigrewe\Sso\Bundle\Security\OidcUserProviderInterface;
use Jostkleigrewe\Sso\Bundle\Service\OidcAuthenticationService;
use Jostkleigrewe\Sso\Client\OidcClient;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * DE: Symfony Bundle für OIDC SSO Integration.
 * EN: Symfony bundle for OIDC SSO integration.
 *
 * @see https://symfony.com/doc/current/bundles/best_practices.html
 */
final class EuripSsoBundle extends AbstractBundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__, 2);
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                // Required settings
                ->scalarNode('issuer')
                    ->isRequired()
                    ->info('OIDC Issuer URL')
                ->end()
                ->scalarNode('client_id')
                    ->isRequired()
                    ->info('OIDC Client ID')
                ->end()
                ->scalarNode('redirect_uri')
                    ->isRequired()
                    ->info('Redirect URI for callback')
                ->end()

                // Optional settings
                ->scalarNode('client_secret')
                    ->defaultNull()
                    ->info('OIDC Client Secret (optional for public clients)')
                ->end()
                ->scalarNode('public_issuer')
                    ->defaultNull()
                    ->info('Public issuer URL for browser redirects (Docker/K8s)')
                ->end()
                ->arrayNode('scopes')
                    ->scalarPrototype()->end()
                    ->defaultValue(['openid', 'profile', 'email'])
                ->end()

                // Cache
                ->arrayNode('cache')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
                        ->integerNode('ttl')->defaultValue(3600)->end()
                        ->scalarNode('pool')->defaultValue('cache.app')->end()
                    ->end()
                ->end()

                // Authenticator (legacy)
                ->arrayNode('authenticator')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('callback_route')->defaultValue('/auth/callback')->end()
                        ->scalarNode('default_target_path')->defaultValue('/')->end()
                        ->scalarNode('login_path')->defaultValue('/login')->end()
                        ->booleanNode('verify_signature')->defaultTrue()->end()
                    ->end()
                ->end()

                // Controller
                ->arrayNode('controller')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                            ->info('Enable bundle-provided auth controller')
                        ->end()
                    ->end()
                ->end()

                // Routes
                ->arrayNode('routes')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('login')->defaultValue('/auth/login')->end()
                        ->scalarNode('callback')->defaultValue('/auth/callback')->end()
                        ->scalarNode('logout')->defaultValue('/auth/logout')->end()
                        ->scalarNode('after_login')->defaultValue('/')->end()
                        ->scalarNode('after_logout')->defaultValue('/')->end()
                        ->scalarNode('profile')->defaultNull()->end()
                        ->scalarNode('debug')->defaultNull()->end()
                        ->scalarNode('test')->defaultNull()->end()
                    ->end()
                ->end()

                // User Provider
                ->arrayNode('user_provider')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                            ->info('Enable Doctrine user provider')
                        ->end()
                        ->scalarNode('entity')
                            ->defaultNull()
                            ->info('User entity class')
                        ->end()
                        ->arrayNode('mapping')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('subject')->defaultValue('oidcSubject')->end()
                                ->scalarNode('issuer')->defaultValue('oidcIssuer')->end()
                                ->scalarNode('email')->defaultNull()->end()
                                ->scalarNode('roles')->defaultNull()->end()
                                ->scalarNode('external_roles')->defaultNull()->end()
                            ->end()
                        ->end()
                        ->arrayNode('claims_sync')
                            ->useAttributeAsKey('claim')
                            ->scalarPrototype()->end()
                        ->end()
                        ->scalarNode('roles_claim')->defaultValue('roles')->end()
                        ->arrayNode('default_roles')
                            ->scalarPrototype()->end()
                            ->defaultValue(['ROLE_USER'])
                        ->end()
                        ->booleanNode('sync_on_login')->defaultTrue()->end()
                        ->booleanNode('auto_create')->defaultTrue()->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        // Set parameters
        $container->parameters()
            ->set('eurip_sso.issuer', $config['issuer'])
            ->set('eurip_sso.client_id', $config['client_id'])
            ->set('eurip_sso.client_secret', $config['client_secret'])
            ->set('eurip_sso.redirect_uri', $config['redirect_uri'])
            ->set('eurip_sso.public_issuer', $config['public_issuer'])
            ->set('eurip_sso.scopes', $config['scopes'])
            ->set('eurip_sso.cache.enabled', $config['cache']['enabled'])
            ->set('eurip_sso.cache.ttl', $config['cache']['ttl'])
            ->set('eurip_sso.cache.pool', $config['cache']['pool'])
            ->set('eurip_sso.authenticator.callback_route', $config['authenticator']['callback_route'])
            ->set('eurip_sso.authenticator.default_target_path', $config['authenticator']['default_target_path'])
            ->set('eurip_sso.authenticator.login_path', $config['authenticator']['login_path'])
            ->set('eurip_sso.authenticator.verify_signature', $config['authenticator']['verify_signature'])
            ->set('eurip_sso.controller.enabled', $config['controller']['enabled'])
            ->set('eurip_sso.routes.login', $config['routes']['login'])
            ->set('eurip_sso.routes.callback', $config['routes']['callback'])
            ->set('eurip_sso.routes.logout', $config['routes']['logout'])
            ->set('eurip_sso.routes.after_login', $config['routes']['after_login'])
            ->set('eurip_sso.routes.after_logout', $config['routes']['after_logout'])
            ->set('eurip_sso.routes.profile', $config['routes']['profile'])
            ->set('eurip_sso.routes.debug', $config['routes']['debug'])
            ->set('eurip_sso.routes.test', $config['routes']['test']);

        // Load base services
        $container->import('../../config/services.yaml');

        // Register OidcClient via static factory
        $this->registerOidcClient($config, $container, $builder);

        // Register controller services
        if ($config['controller']['enabled']) {
            $this->registerControllerServices($config, $container, $builder);
        }

        // Register user provider
        if ($config['user_provider']['enabled']) {
            $this->registerUserProvider($config, $container, $builder);
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private function registerOidcClient(
        array $config,
        ContainerConfigurator $container,
        ContainerBuilder $builder,
    ): void {
        $services = $container->services();

        // Build arguments for static factory
        $factoryArgs = [
            '$issuer' => $config['issuer'],
            '$clientId' => $config['client_id'],
            '$redirectUri' => $config['redirect_uri'],
            '$httpClient' => new Reference(ClientInterface::class),
            '$requestFactory' => new Reference(RequestFactoryInterface::class),
            '$streamFactory' => new Reference(StreamFactoryInterface::class),
            '$clientSecret' => $config['client_secret'],
            '$publicIssuer' => $config['public_issuer'],
            '$cacheTtl' => $config['cache']['ttl'],
            '$logger' => new Reference('logger', $builder::NULL_ON_INVALID_REFERENCE),
        ];

        // Add cache if enabled
        if ($config['cache']['enabled']) {
            $factoryArgs['$cache'] = new Reference($config['cache']['pool']);
        } else {
            $factoryArgs['$cache'] = null;
        }

        $services->set(OidcClient::class)
            ->factory([OidcClientFactory::class, 'create'])
            ->args($factoryArgs);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function registerControllerServices(
        array $config,
        ContainerConfigurator $container,
        ContainerBuilder $builder,
    ): void {
        $services = $container->services();

        // Session Storage
        $services->set(OidcSessionStorage::class)
            ->arg('$requestStack', new Reference('request_stack'))
            ->autowire();

        // Authentication Service (shared business logic)
        $services->set(OidcAuthenticationService::class)
            ->arg('$oidcClient', new Reference(OidcClient::class))
            ->arg('$userProvider', new Reference(OidcUserProviderInterface::class))
            ->arg('$sessionStorage', new Reference(OidcSessionStorage::class))
            ->arg('$eventDispatcher', new Reference('event_dispatcher'))
            ->arg('$logger', new Reference('logger', $builder::NULL_ON_INVALID_REFERENCE));

        // Route Loader
        $services->set(OidcRouteLoader::class)
            ->arg('$loginPath', $config['routes']['login'])
            ->arg('$callbackPath', $config['routes']['callback'])
            ->arg('$logoutPath', $config['routes']['logout'])
            ->arg('$optionalRoutes', [
                'profile' => $config['routes']['profile'],
                'debug' => $config['routes']['debug'],
                'test' => $config['routes']['test'],
            ])
            ->tag('routing.loader');

        $services->alias('eurip_sso.route_loader', OidcRouteLoader::class);

        // Authentication Controller (login, callback, logout)
        $services->set(AuthenticationController::class)
            ->arg('$authService', new Reference(OidcAuthenticationService::class))
            ->arg('$tokenStorage', new Reference('security.token_storage'))
            ->arg('$logger', new Reference('logger', $builder::NULL_ON_INVALID_REFERENCE))
            ->arg('$defaultTargetPath', $config['routes']['after_login'])
            ->arg('$afterLogoutPath', $config['routes']['after_logout'])
            ->arg('$scopes', $config['scopes'])
            ->arg('$firewallName', 'main')
            ->autowire()
            ->autoconfigure()
            ->tag('controller.service_arguments')
            ->public();

        // Profile Controller (optional)
        if ($config['routes']['profile'] !== null) {
            $services->set(ProfileController::class)
                ->arg('$loginPath', $config['routes']['login'])
                ->autowire()
                ->autoconfigure()
                ->tag('controller.service_arguments')
                ->public();
        }

        // Diagnostics Controller (debug, test - optional)
        if ($config['routes']['debug'] !== null || $config['routes']['test'] !== null) {
            $services->set(DiagnosticsController::class)
                ->arg('$oidcClient', new Reference(OidcClient::class))
                ->arg('$scopes', $config['scopes'])
                ->autowire()
                ->autoconfigure()
                ->tag('controller.service_arguments')
                ->public();
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private function registerUserProvider(
        array $config,
        ContainerConfigurator $container,
        ContainerBuilder $builder,
    ): void {
        $providerConfig = $config['user_provider'];

        if ($providerConfig['entity'] === null) {
            throw new \InvalidArgumentException(
                'eurip_sso.user_provider.entity must be set when user_provider.enabled is true'
            );
        }

        $services = $container->services();

        $services->set(DoctrineOidcUserProvider::class)
            ->arg('$entityManager', new Reference('doctrine.orm.entity_manager'))
            ->arg('$propertyAccessor', new Reference('property_accessor'))
            ->arg('$eventDispatcher', new Reference('event_dispatcher'))
            ->arg('$entityClass', $providerConfig['entity'])
            ->arg('$mapping', $providerConfig['mapping'])
            ->arg('$claimsSync', $providerConfig['claims_sync'])
            ->arg('$rolesClaim', $providerConfig['roles_claim'])
            ->arg('$defaultRoles', $providerConfig['default_roles'])
            ->arg('$syncOnLogin', $providerConfig['sync_on_login'])
            ->arg('$autoCreate', $providerConfig['auto_create'])
            ->arg('$logger', new Reference('logger', $builder::NULL_ON_INVALID_REFERENCE));

        $services->alias(OidcUserProviderInterface::class, DoctrineOidcUserProvider::class);
    }
}
