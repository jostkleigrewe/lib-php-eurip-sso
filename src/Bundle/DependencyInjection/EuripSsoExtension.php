<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class EuripSsoExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->setParameter('eurip_sso.issuer', $config['issuer']);
        $container->setParameter('eurip_sso.client_id', $config['client_id']);
        $container->setParameter('eurip_sso.client_secret', $config['client_secret']);
        $container->setParameter('eurip_sso.redirect_uri', $config['redirect_uri']);
        $container->setParameter('eurip_sso.scopes', $config['scopes']);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../../Resources/config'));
        $loader->load('services.yaml');
    }
}
