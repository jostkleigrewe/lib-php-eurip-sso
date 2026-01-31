<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Factory;

use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * DE: Factory für OidcClient mit Discovery-Support und Caching.
 * EN: Factory for OidcClient with discovery support and caching.
 */
final class OidcClientFactory
{
    private const CACHE_TTL = 3600; // 1 hour

    /**
     * @throws OidcProtocolException
     */
    public static function create(
        string $issuer,
        string $clientId,
        string $redirectUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        ?string $clientSecret = null,
        ?string $publicIssuer = null,
        ?CacheInterface $cache = null,
        int $cacheTtl = self::CACHE_TTL,
        ?LoggerInterface $logger = null,
    ): OidcClient {
        $config = self::fetchConfig(
            issuer: $issuer,
            clientId: $clientId,
            redirectUri: $redirectUri,
            clientSecret: $clientSecret,
            publicIssuer: $publicIssuer,
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            cache: $cache,
            cacheTtl: $cacheTtl,
            logger: $logger,
        );

        return new OidcClient($config, $httpClient, $requestFactory, $streamFactory, $logger);
    }

    /**
     * @throws OidcProtocolException
     */
    private static function fetchConfig(
        string $issuer,
        string $clientId,
        string $redirectUri,
        ?string $clientSecret,
        ?string $publicIssuer,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        ?CacheInterface $cache,
        int $cacheTtl,
        ?LoggerInterface $logger,
    ): OidcClientConfig {
        $fetchDiscovery = static function () use ($issuer, $clientId, $redirectUri, $clientSecret, $publicIssuer, $httpClient, $requestFactory, $logger): OidcClientConfig {
            return self::fetchDiscovery($issuer, $clientId, $redirectUri, $clientSecret, $publicIssuer, $httpClient, $requestFactory, $logger);
        };

        if ($cache === null) {
            return $fetchDiscovery();
        }

        $cacheKey = 'eurip_sso.discovery.' . hash('xxh3', $issuer);

        /** @var OidcClientConfig */
        return $cache->get($cacheKey, static function (ItemInterface $item) use ($fetchDiscovery, $cacheTtl): OidcClientConfig {
            $item->expiresAfter($cacheTtl);

            return $fetchDiscovery();
        });
    }

    /**
     * @throws OidcProtocolException
     */
    private static function fetchDiscovery(
        string $issuer,
        string $clientId,
        string $redirectUri,
        ?string $clientSecret,
        ?string $publicIssuer,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        ?LoggerInterface $logger,
    ): OidcClientConfig {
        $discoveryUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        $logger?->debug('Fetching OIDC discovery document', ['url' => $discoveryUrl]);

        $request = $requestFactory->createRequest('GET', $discoveryUrl)
            ->withHeader('Accept', 'application/json');

        $response = $httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            $logger?->error('Discovery request failed', ['status_code' => $response->getStatusCode()]);
            throw new OidcProtocolException('Discovery request failed: ' . $response->getStatusCode());
        }

        $discovery = json_decode((string) $response->getBody(), true);

        if (!is_array($discovery)) {
            throw new OidcProtocolException('Invalid discovery document');
        }

        $logger?->info('OIDC discovery document fetched successfully', [
            'issuer' => $discovery['issuer'] ?? $issuer,
        ]);

        // Build authorization endpoint with public issuer if configured
        $authorizationEndpoint = $discovery['authorization_endpoint']
            ?? throw new OidcProtocolException('Missing authorization_endpoint');
        $endSessionEndpoint = $discovery['end_session_endpoint'] ?? null;

        // Replace internal issuer with public issuer in browser-facing endpoints
        if ($publicIssuer !== null) {
            $internalIssuer = rtrim($discovery['issuer'] ?? $issuer, '/');
            $publicIssuerNormalized = rtrim($publicIssuer, '/');

            $authorizationEndpoint = str_replace($internalIssuer, $publicIssuerNormalized, $authorizationEndpoint);

            if ($endSessionEndpoint !== null) {
                $endSessionEndpoint = str_replace($internalIssuer, $publicIssuerNormalized, $endSessionEndpoint);
            }
        }

        return new OidcClientConfig(
            clientId: $clientId,
            issuer: $discovery['issuer'] ?? $issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $discovery['token_endpoint'] ?? throw new OidcProtocolException('Missing token_endpoint'),
            jwksUri: $discovery['jwks_uri'] ?? '',
            redirectUri: $redirectUri,
            userInfoEndpoint: $discovery['userinfo_endpoint'] ?? '',
            endSessionEndpoint: $endSessionEndpoint,
            clientSecret: $clientSecret,
            publicIssuer: $publicIssuer,
        );
    }
}
