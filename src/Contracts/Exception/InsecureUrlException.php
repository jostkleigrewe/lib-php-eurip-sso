<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Contracts\Exception;

/**
 * DE: Exception für unsichere (nicht-HTTPS) URLs in OIDC-Konfiguration.
 * EN: Exception for insecure (non-HTTPS) URLs in OIDC configuration.
 */
final class InsecureUrlException extends OidcProtocolException
{
    /**
     * DE: Erzeugt Exception für unsicheren Issuer.
     * EN: Creates exception for insecure issuer.
     */
    public static function forIssuer(string $issuer): self
    {
        return new self(sprintf(
            'Insecure issuer URL "%s" - HTTPS is required. Set requireHttps: false for local development only.',
            $issuer
        ));
    }

    /**
     * DE: Erzeugt Exception für unsicheren Endpoint.
     * EN: Creates exception for insecure endpoint.
     */
    public static function forEndpoint(string $endpointName, string $url): self
    {
        return new self(sprintf(
            'Insecure %s URL "%s" - HTTPS is required. Set requireHttps: false for local development only.',
            $endpointName,
            $url
        ));
    }
}
