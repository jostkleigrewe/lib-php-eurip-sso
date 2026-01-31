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

        // Get endpoints from discovery
        $authorizationEndpoint = $discovery['authorization_endpoint']
            ?? throw new OidcProtocolException('Missing authorization_endpoint');
        $tokenEndpoint = $discovery['token_endpoint']
            ?? throw new OidcProtocolException('Missing token_endpoint');
        $jwksUri = $discovery['jwks_uri'] ?? '';
        $userInfoEndpoint = $discovery['userinfo_endpoint'] ?? '';
        $endSessionEndpoint = $discovery['end_session_endpoint'] ?? null;

        // Handle dual-URL setup (internal issuer for server-to-server, public issuer for browser)
        // Discovery document may contain public URLs, we need to:
        // - Keep public URLs for browser-facing endpoints (authorization, end_session)
        // - Use internal URLs for server-to-server endpoints (token, userinfo, jwks)
        if ($publicIssuer !== null) {
            $internalIssuerNormalized = rtrim($issuer, '/');
            $publicIssuerNormalized = rtrim($publicIssuer, '/');
            $discoveryIssuer = rtrim($discovery['issuer'] ?? $issuer, '/');

            // If discovery issuer matches public issuer, replace with internal for server endpoints
            if ($discoveryIssuer === $publicIssuerNormalized) {
                $tokenEndpoint = str_replace($publicIssuerNormalized, $internalIssuerNormalized, $tokenEndpoint);
                $userInfoEndpoint = str_replace($publicIssuerNormalized, $internalIssuerNormalized, $userInfoEndpoint);
                $jwksUri = str_replace($publicIssuerNormalized, $internalIssuerNormalized, $jwksUri);
            }
            // If discovery issuer matches internal issuer, replace with public for browser endpoints
            elseif ($discoveryIssuer === $internalIssuerNormalized) {
                $authorizationEndpoint = str_replace($internalIssuerNormalized, $publicIssuerNormalized, $authorizationEndpoint);
                if ($endSessionEndpoint !== null) {
                    $endSessionEndpoint = str_replace($internalIssuerNormalized, $publicIssuerNormalized, $endSessionEndpoint);
                }
            }
        }

        return new OidcClientConfig(
            clientId: $clientId,
            issuer: $discovery['issuer'] ?? $issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $tokenEndpoint,
            jwksUri: $jwksUri,
            redirectUri: $redirectUri,
            userInfoEndpoint: $userInfoEndpoint,
            endSessionEndpoint: $endSessionEndpoint,
            clientSecret: $clientSecret,
            publicIssuer: $publicIssuer,
        );
    }
}
