<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('eurip_sso');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('issuer')
                    ->isRequired()
                    ->info('OIDC Issuer URL (e.g. https://sso.example.com)')
                ->end()
                ->scalarNode('client_id')
                    ->isRequired()
                    ->info('OIDC Client ID')
                ->end()
                ->scalarNode('client_secret')
                    ->defaultNull()
                    ->info('OIDC Client Secret (optional for public clients)')
                ->end()
                ->scalarNode('redirect_uri')
                    ->isRequired()
                    ->info('Redirect URI for authorization callback')
                ->end()
                ->scalarNode('public_issuer')
                    ->defaultNull()
                    ->info('Public issuer URL for browser redirects (if different from issuer)')
                ->end()
                ->arrayNode('scopes')
                    ->scalarPrototype()->end()
                    ->defaultValue(['openid', 'profile', 'email'])
                    ->info('OIDC scopes to request')
                ->end()
                ->arrayNode('cache')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                            ->info('Enable discovery document caching')
                        ->end()
                        ->integerNode('ttl')
                            ->defaultValue(3600)
                            ->info('Cache TTL in seconds (default: 1 hour)')
                        ->end()
                        ->scalarNode('pool')
                            ->defaultValue('cache.app')
                            ->info('Cache pool service ID')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('authenticator')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('callback_route')
                            ->defaultValue('/auth/callback')
                            ->info('Path where the SSO callback is handled')
                        ->end()
                        ->scalarNode('default_target_path')
                            ->defaultValue('/')
                            ->info('Default redirect path after successful login')
                        ->end()
                        ->scalarNode('login_path')
                            ->defaultValue('/login')
                            ->info('Path to redirect to on authentication failure')
                        ->end()
                        ->booleanNode('verify_signature')
                            ->defaultFalse()
                            ->info('Verify ID token signature via JWKS')
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
