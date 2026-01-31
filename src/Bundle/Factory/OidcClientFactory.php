<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Factory;

use Jostkleigrewe\Sso\Client\OidcClient;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * DE: Factory für OidcClient mit Discovery-Support.
 * EN: Factory for OidcClient with discovery support.
 */
final class OidcClientFactory
{
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
    }

    public function create(
        string $issuer,
        string $clientId,
        string $redirectUri,
        ?string $clientSecret = null,
    ): OidcClient {
        return OidcClient::fromDiscovery(
            issuer: $issuer,
            clientId: $clientId,
            redirectUri: $redirectUri,
            httpClient: $this->httpClient,
            requestFactory: $this->requestFactory,
            streamFactory: $this->streamFactory,
            clientSecret: $clientSecret,
        );
    }
}
