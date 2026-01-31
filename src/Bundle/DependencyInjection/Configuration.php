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
                ->arrayNode('scopes')
                    ->scalarPrototype()->end()
                    ->defaultValue(['openid', 'profile', 'email'])
                    ->info('OIDC scopes to request')
                ->end()
            ->end();

        return $treeBuilder;
    }
}
