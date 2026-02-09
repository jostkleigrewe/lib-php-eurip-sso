<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Factory;

use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\DTO\DiscoveryDocument;
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
    private const JWKS_CACHE_TTL = 600; // DE: 10 Minuten für schnellere Key-Rotation // EN: 10 minutes for faster key rotation
    private const CACHE_VERSION = 'v1'; // DE: Bei Breaking Changes hochzählen // EN: Increment on breaking changes

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

        // DE: JwtVerifier erzeugen (für JWT-Signatur-Validierung via JWKS)
        // EN: Create JwtVerifier (for JWT signature validation via JWKS)
        $jwtVerifier = new JwtVerifier($config->jwksUri, $httpClient, $requestFactory, $logger);

        $client = new OidcClient($config, $httpClient, $requestFactory, $streamFactory, $jwtVerifier, $logger);

        // DE: JWKS vorab laden und cachen (für JWT-Signatur-Validierung)
        // EN: Preload and cache JWKS (for JWT signature validation)
        if ($cache !== null && $config->jwksUri !== '') {
            self::preloadJwks($jwtVerifier, $config->jwksUri, $httpClient, $requestFactory, $cache, $logger);
        }

        return $client;
    }

    /**
     * DE: Erzeugt den Cache-Key für JWKS (shared zwischen Factory + Warmup-Command).
     * EN: Builds the cache key for JWKS (shared between factory + warmup command).
     */
    public static function buildJwksCacheKey(string $jwksUri): string
    {
        return sprintf('eurip_sso.jwks.%s.%s', self::CACHE_VERSION, hash('xxh3', $jwksUri));
    }

    /**
     * DE: Lädt JWKS aus Cache oder vom IdP und übergibt sie an den Client.
     * EN: Loads JWKS from cache or IdP and passes them to the client.
     */
    private static function preloadJwks(
        JwtVerifier $jwtVerifier,
        string $jwksUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        CacheInterface $cache,
        ?LoggerInterface $logger,
    ): void {
        $cacheKey = self::buildJwksCacheKey($jwksUri);

        try {
            /** @var array<string, mixed> $jwks */
            $jwks = $cache->get($cacheKey, static function (ItemInterface $item) use ($jwksUri, $httpClient, $requestFactory, $logger): array {
                $item->expiresAfter(self::JWKS_CACHE_TTL);

                $logger?->debug('Fetching JWKS for cache', ['uri' => $jwksUri]);

                $request = $requestFactory->createRequest('GET', $jwksUri)
                    ->withHeader('Accept', 'application/json');

                $response = $httpClient->sendRequest($request);

                if ($response->getStatusCode() !== 200) {
                    throw new OidcProtocolException('JWKS request failed: ' . $response->getStatusCode());
                }

                $data = json_decode((string) $response->getBody(), true);

                if (!is_array($data) || !isset($data['keys'])) {
                    throw new OidcProtocolException('Invalid JWKS response');
                }

                $logger?->info('JWKS cached successfully', ['keys_count' => count($data['keys'])]);

                return $data;
            });

            $jwtVerifier->preloadJwks($jwks);
        } catch (\Throwable $e) {
            // DE: Bei Fehlern nicht abbrechen - JWKS werden on-demand geladen
            // EN: Don't fail on errors - JWKS will be loaded on-demand
            $logger?->warning('Failed to preload JWKS, will load on-demand', [
                'error' => $e->getMessage(),
            ]);
        }
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

        $cacheKey = sprintf('eurip_sso.discovery.%s.%s', self::CACHE_VERSION, hash('xxh3', $issuer));

        /** @var OidcClientConfig */
        return $cache->get($cacheKey, static function (ItemInterface $item) use ($fetchDiscovery, $cacheTtl): OidcClientConfig {
            $item->expiresAfter($cacheTtl);

            return $fetchDiscovery();
        });
    }

    /**
     * DE: Prüft ob eine URL HTTPS verwendet (oder ein erlaubtes Dev-Schema).
     * EN: Checks if a URL uses HTTPS (or an allowed dev scheme).
     */
    private static function isSecureUrl(string $url): bool
    {
        if (str_starts_with($url, 'https://')) {
            return true;
        }

        // DE: Erlaubte Development-URLs // EN: Allowed development URLs
        $devPrefixes = [
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://host.docker.internal',
        ];

        foreach ($devPrefixes as $prefix) {
            if (str_starts_with($url, $prefix)) {
                return true;
            }
        }

        return false;
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
        // DE: HTTPS-Validierung für Issuer // EN: HTTPS validation for issuer
        if (!self::isSecureUrl($issuer)) {
            $logger?->warning('Insecure issuer URL detected - HTTPS is required in production', [
                'issuer' => $issuer,
            ]);
        }

        $discoveryUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        $logger?->debug('Fetching OIDC discovery document', ['url' => $discoveryUrl]);

        $request = $requestFactory->createRequest('GET', $discoveryUrl)
            ->withHeader('Accept', 'application/json');

        $response = $httpClient->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            $logger?->error('Discovery request failed', ['status_code' => $response->getStatusCode()]);
            throw new OidcProtocolException('Discovery request failed: ' . $response->getStatusCode());
        }

        $body = (string) $response->getBody();
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $logger?->error('Invalid JSON in discovery document', [
                'error' => json_last_error_msg(),
                'body_preview' => substr($body, 0, 200),
            ]);
            throw new OidcProtocolException('Invalid JSON in discovery document: ' . json_last_error_msg());
        }

        if (!is_array($data)) {
            throw new OidcProtocolException('Discovery document must be a JSON object');
        }

        // DE: Discovery-Dokument als DTO parsen (inkl. Validierung)
        // EN: Parse discovery document as DTO (incl. validation)
        $discovery = DiscoveryDocument::fromArray($data);

        $logger?->info('OIDC discovery document fetched successfully', [
            'issuer' => $discovery->issuer,
        ]);

        // DE: Endpoints aus DTO extrahieren
        // EN: Extract endpoints from DTO
        $authorizationEndpoint = $discovery->authorizationEndpoint;
        $tokenEndpoint = $discovery->tokenEndpoint;
        $jwksUri = $discovery->jwksUri ?? '';
        $userinfoEndpoint = $discovery->userinfoEndpoint ?? '';
        $endSessionEndpoint = $discovery->endSessionEndpoint;
        $revocationEndpoint = $discovery->revocationEndpoint;
        $introspectionEndpoint = $discovery->introspectionEndpoint;

        // DE: HTTPS-Validierung für kritische Server-to-Server Endpoints
        // EN: HTTPS validation for critical server-to-server endpoints
        $criticalEndpoints = [
            'token_endpoint' => $tokenEndpoint,
            'jwks_uri' => $jwksUri,
            'userinfo_endpoint' => $userinfoEndpoint,
        ];

        foreach ($criticalEndpoints as $name => $url) {
            if ($url !== '' && !self::isSecureUrl($url)) {
                $logger?->warning('Insecure endpoint detected - HTTPS is required in production', [
                    'endpoint' => $name,
                    'url' => $url,
                ]);
            }
        }

        // DE: Dual-URL-Setup (interner Issuer für Server-to-Server, public Issuer für Browser)
        // EN: Handle dual-URL setup (internal issuer for server-to-server, public issuer for browser)
        // Discovery document may contain public URLs, we need to:
        // - Keep public URLs for browser-facing endpoints (authorization, end_session)
        // - Use internal URLs for server-to-server endpoints (token, userinfo, jwks)
        if ($publicIssuer !== null) {
            $internalIssuerNormalized = rtrim($issuer, '/');
            $publicIssuerNormalized = rtrim($publicIssuer, '/');
            $discoveryIssuer = rtrim($discovery->issuer, '/');

            // DE: Discovery-Issuer entspricht public Issuer → Server-Endpoints auf internal umschreiben
            // EN: Discovery issuer matches public issuer → rewrite server endpoints to internal
            if ($discoveryIssuer === $publicIssuerNormalized) {
                $tokenEndpoint = self::replaceIssuerInUrl($tokenEndpoint, $publicIssuerNormalized, $internalIssuerNormalized);
                $userinfoEndpoint = self::replaceIssuerInUrl($userinfoEndpoint, $publicIssuerNormalized, $internalIssuerNormalized);
                $jwksUri = self::replaceIssuerInUrl($jwksUri, $publicIssuerNormalized, $internalIssuerNormalized);
                if ($revocationEndpoint !== null) {
                    $revocationEndpoint = self::replaceIssuerInUrl($revocationEndpoint, $publicIssuerNormalized, $internalIssuerNormalized);
                }
                if ($introspectionEndpoint !== null) {
                    $introspectionEndpoint = self::replaceIssuerInUrl($introspectionEndpoint, $publicIssuerNormalized, $internalIssuerNormalized);
                }
            }
            // DE: Discovery-Issuer entspricht internal Issuer → Browser-Endpoints auf public umschreiben
            // EN: Discovery issuer matches internal issuer → rewrite browser endpoints to public
            elseif ($discoveryIssuer === $internalIssuerNormalized) {
                $authorizationEndpoint = self::replaceIssuerInUrl($authorizationEndpoint, $internalIssuerNormalized, $publicIssuerNormalized);
                if ($endSessionEndpoint !== null) {
                    $endSessionEndpoint = self::replaceIssuerInUrl($endSessionEndpoint, $internalIssuerNormalized, $publicIssuerNormalized);
                }
            }
        }

        return new OidcClientConfig(
            clientId: $clientId,
            issuer: $discovery->issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $tokenEndpoint,
            jwksUri: $jwksUri,
            redirectUri: $redirectUri,
            userInfoEndpoint: $userinfoEndpoint,
            endSessionEndpoint: $endSessionEndpoint,
            clientSecret: $clientSecret,
            publicIssuer: $publicIssuer,
            revocationEndpoint: $revocationEndpoint,
            introspectionEndpoint: $introspectionEndpoint,
        );
    }

    /**
     * DE: Ersetzt den Issuer-Teil einer URL sicher (nur am Anfang).
     * EN: Safely replaces the issuer part of a URL (only at the beginning).
     */
    private static function replaceIssuerInUrl(string $url, string $from, string $to): string
    {
        if ($url === '' || !str_starts_with($url, $from)) {
            return $url;
        }

        return $to . substr($url, strlen($from));
    }
}
