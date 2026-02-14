<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Service;

use Jostkleigrewe\Sso\Bundle\Factory\OidcClientFactory;
use Jostkleigrewe\Sso\Client\JwtVerifier;
use Jostkleigrewe\Sso\Client\OidcClient;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * DE: Service für OIDC Cache-Management.
 *     Ermöglicht das gezielte Löschen von Discovery- und JWKS-Cache.
 *
 * EN: Service for OIDC cache management.
 *     Allows targeted clearing of discovery and JWKS cache.
 */
final class OidcCacheService
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly JwtVerifier $jwtVerifier,
        private readonly ?CacheItemPoolInterface $cache = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * DE: Löscht den kompletten OIDC-Cache (Discovery + JWKS).
     *     Nützlich bei invalid_client Fehlern nach Secret-Änderungen.
     *
     * EN: Clears the complete OIDC cache (discovery + JWKS).
     *     Useful for invalid_client errors after secret changes.
     */
    public function clearAll(): void
    {
        $this->clearDiscoveryCache();
        $this->clearJwksCache();
    }

    /**
     * DE: Löscht den Discovery-Cache (enthält auch das clientSecret).
     * EN: Clears the discovery cache (also contains clientSecret).
     */
    public function clearDiscoveryCache(): void
    {
        if ($this->cache === null) {
            return;
        }

        $config = $this->oidcClient->getConfig();
        $cacheKey = $this->buildDiscoveryCacheKey($config->issuer, $config->publicIssuer);

        if ($this->cache->deleteItem($cacheKey)) {
            $this->logger?->info('OIDC discovery cache cleared', [
                'issuer' => $config->issuer,
            ]);
        }
    }

    /**
     * DE: Löscht den JWKS-Cache.
     * EN: Clears the JWKS cache.
     */
    public function clearJwksCache(): void
    {
        $this->jwtVerifier->invalidateJwksCache();
        $this->logger?->info('OIDC JWKS cache cleared');
    }

    /**
     * DE: Baut den Cache-Key für Discovery (muss mit OidcClientFactory übereinstimmen).
     * EN: Builds the cache key for discovery (must match OidcClientFactory).
     */
    private function buildDiscoveryCacheKey(string $issuer, ?string $publicIssuer): string
    {
        return sprintf(
            'eurip_sso.discovery.%s.%s',
            OidcClientFactory::CACHE_VERSION,
            hash('xxh3', $issuer . '|' . ($publicIssuer ?? ''))
        );
    }
}
