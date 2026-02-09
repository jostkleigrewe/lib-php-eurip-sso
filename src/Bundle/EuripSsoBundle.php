<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle;

use Jostkleigrewe\Sso\Bundle\Controller\BackchannelLogoutController;
use Jostkleigrewe\Sso\Bundle\Controller\FrontchannelLogoutController;
use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;
use Jostkleigrewe\Sso\Bundle\Security\DoctrineOidcUserProvider;
use Jostkleigrewe\Sso\Bundle\Security\OidcAuthenticator;
use Jostkleigrewe\Sso\Bundle\Security\OidcUserProviderInterface;
use Jostkleigrewe\Sso\Client\JwtVerifier;
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

                // Security
                ->booleanNode('require_https')
                    ->defaultTrue()
                    ->info('Require HTTPS for all OIDC endpoints (disable only for local development)')
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

                // Authenticator
                ->arrayNode('authenticator')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                            ->info('Enable OidcAuthenticator for Symfony Security')
                        ->end()
                        ->booleanNode('verify_signature')->defaultTrue()->end()
                    ->end()
                ->end()

                // Routes
                ->arrayNode('routes')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('login')->defaultValue('/auth/login')->end()
                        ->scalarNode('callback')->defaultValue('/auth/callback')->end()
                        ->scalarNode('logout')->defaultValue('/auth/logout')->end()
                        ->scalarNode('logout_confirm')
                            ->defaultValue('/auth/logout/confirm')
                            ->info('GET endpoint for logout confirmation page')
                        ->end()
                        ->scalarNode('after_login')->defaultValue('/')->end()
                        ->scalarNode('after_logout')->defaultValue('/')->end()
                        ->scalarNode('profile')->defaultValue('/auth/profile')->end()
                        ->scalarNode('debug')->defaultValue('/auth/debug')->end()
                        ->scalarNode('test')->defaultValue('/auth/test')->end()
                        ->scalarNode('error')
                            ->defaultValue('/auth/error')
                            ->info('Error page for authentication failures (prevents redirect loops)')
                        ->end()
                        // DE: OpenID Connect Logout Extensions
                        // EN: OpenID Connect Logout Extensions
                        ->scalarNode('backchannel_logout')
                            ->defaultNull()
                            ->info('Back-Channel Logout endpoint (POST)')
                        ->end()
                        ->scalarNode('frontchannel_logout')
                            ->defaultNull()
                            ->info('Front-Channel Logout endpoint (GET, iframe)')
                        ->end()
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
        // DE: Container-Parameter setzen (für #[Autowire]-Attribute)
        // EN: Set container parameters (for #[Autowire] attributes)
        $container->parameters()
            ->set('eurip_sso.issuer', $config['issuer'])
            ->set('eurip_sso.client_id', $config['client_id'])
            ->set('eurip_sso.client_secret', $config['client_secret'])
            ->set('eurip_sso.redirect_uri', $config['redirect_uri'])
            ->set('eurip_sso.public_issuer', $config['public_issuer'])
            ->set('eurip_sso.scopes', $config['scopes'])
            ->set('eurip_sso.require_https', $config['require_https'])
            ->set('eurip_sso.cache.enabled', $config['cache']['enabled'])
            ->set('eurip_sso.cache.ttl', $config['cache']['ttl'])
            ->set('eurip_sso.cache.pool', $config['cache']['pool'])
            ->set('eurip_sso.authenticator.verify_signature', $config['authenticator']['verify_signature'])
            ->set('eurip_sso.routes.login', $config['routes']['login'])
            ->set('eurip_sso.routes.callback', $config['routes']['callback'])
            ->set('eurip_sso.routes.logout', $config['routes']['logout'])
            ->set('eurip_sso.routes.logout_confirm', $config['routes']['logout_confirm'])
            ->set('eurip_sso.routes.after_login', $config['routes']['after_login'])
            ->set('eurip_sso.routes.after_logout', $config['routes']['after_logout'])
            ->set('eurip_sso.routes.profile', $config['routes']['profile'])
            ->set('eurip_sso.routes.debug', $config['routes']['debug'])
            ->set('eurip_sso.routes.test', $config['routes']['test'])
            ->set('eurip_sso.routes.error', $config['routes']['error'])
            ->set('eurip_sso.routes.backchannel_logout', $config['routes']['backchannel_logout'])
            ->set('eurip_sso.routes.frontchannel_logout', $config['routes']['frontchannel_logout']);

        // DE: Services via Resource-Scanning laden (#[Autowire] löst skalare Params auf)
        // EN: Load services via resource scanning (#[Autowire] resolves scalar params)
        $container->import('../../config/services.yaml');

        // DE: OidcClient + JwtVerifier via Static Factory registrieren
        // EN: Register OidcClient + JwtVerifier via static factory
        $this->registerOidcClient($config, $container, $builder);

        // DE: OidcAuthenticator bedingt registrieren
        // EN: Conditionally register OidcAuthenticator
        if ($config['authenticator']['enabled']) {
            $container->services()
                ->set(OidcAuthenticator::class)
                ->autowire()
                ->autoconfigure();
        }

        // DE: DoctrineOidcUserProvider bedingt registrieren (Doctrine-Abhängigkeit)
        // EN: Conditionally register DoctrineOidcUserProvider (Doctrine dependency)
        if ($config['user_provider']['enabled']) {
            $this->registerUserProvider($config, $container, $builder);
        }

        // DE: Logout-Channel-Controller entfernen wenn Route nicht konfiguriert
        // EN: Remove logout channel controllers when route not configured
        if ($config['routes']['backchannel_logout'] === null) {
            $builder->removeDefinition(BackchannelLogoutController::class);
        }
        if ($config['routes']['frontchannel_logout'] === null) {
            $builder->removeDefinition(FrontchannelLogoutController::class);
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
        $factoryArgs = [
            '$issuer' => $config['issuer'],
            '$clientId' => $config['client_id'],
            '$redirectUri' => $config['redirect_uri'],
            '$httpClient' => new Reference(ClientInterface::class),
            '$requestFactory' => new Reference(RequestFactoryInterface::class),
            '$streamFactory' => new Reference(StreamFactoryInterface::class),
            '$clientSecret' => $config['client_secret'],
            '$publicIssuer' => $config['public_issuer'],
            '$cache' => $config['cache']['enabled']
                ? new Reference($config['cache']['pool'])
                : null,
            '$cacheTtl' => $config['cache']['ttl'],
            '$logger' => new Reference('logger', $builder::NULL_ON_INVALID_REFERENCE),
            '$requireHttps' => $config['require_https'],
        ];

        $container->services()
            ->set(OidcClient::class)
            ->factory([OidcClientFactory::class, 'create'])
            ->args($factoryArgs);

        // DE: JwtVerifier als Service registrieren (gleiche Instanz wie im OidcClient)
        // EN: Register JwtVerifier as service (same instance as in OidcClient)
        $container->services()
            ->set(JwtVerifier::class)
            ->factory([new Reference(OidcClient::class), 'getJwtVerifier']);
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
