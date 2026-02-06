<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Oidc\OidcClientConfig;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Routing\RouterInterface;

/**
 * DE: Console Command zum Testen der SSO-Verbindung.
 *     Prüft alle OIDC-Endpoints auf Erreichbarkeit.
 *     Unterscheidet zwischen Server-Endpoints (intern) und Browser-Endpoints (öffentlich).
 * EN: Console command to test the SSO connection.
 *     Checks all OIDC endpoints for reachability.
 *     Distinguishes between server endpoints (internal) and browser endpoints (public).
 */
#[AsCommand(
    name: 'eurip:sso:test-connection',
    description: 'Test connectivity to SSO server endpoints',
)]
final class OidcTestConnectionCommand extends Command
{
    private const TIMEOUT_WARNING_MS = 1000;
    private const TIMEOUT_CRITICAL_MS = 3000;

    /**
     * DE: Endpoint-Typ für die Kategorisierung.
     * EN: Endpoint type for categorization.
     */
    private const TYPE_SERVER = 'server';
    private const TYPE_BROWSER = 'browser';
    private const TYPE_ROUTE = 'route';

    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ?RouterInterface $router = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'skip-browser',
                null,
                InputOption::VALUE_NONE,
                'Skip browser-facing endpoints (not reachable from container)'
            )
            ->addOption(
                'skip-routes',
                null,
                InputOption::VALUE_NONE,
                'Skip bundle route checks'
            )
            ->setHelp(
                <<<'HELP'
The <info>%command.name%</info> command tests connectivity to all SSO server endpoints.

It distinguishes between:
  <fg=cyan>Server endpoints</> (internal URLs, must be reachable from container):
    - Discovery (internal)
    - JWKS endpoint
    - Token endpoint
    - UserInfo endpoint
    - Revocation endpoint (if available)
    - Introspection endpoint (if available)

  <fg=yellow>Browser endpoints</> (public URLs, may not be reachable from container):
    - Discovery (public)
    - Authorization endpoint
    - End-Session endpoint

  <fg=magenta>Bundle routes</> (local routes, must be registered):
    - Login, Callback, Logout routes
    - Optional routes (profile, debug, test)
    - Logout endpoints (backchannel, frontchannel)

<info>php %command.full_name%</info>
<info>php %command.full_name% --skip-browser</info>
<info>php %command.full_name% --skip-routes</info>

Returns exit code 0 if all server endpoints are reachable, 1 otherwise.
Browser endpoint failures are warnings only.
HELP
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('SSO Connection Test');

        $config = $this->oidcClient->getConfig();
        $skipBrowser = $input->getOption('skip-browser');
        $skipRoutes = $input->getOption('skip-routes');

        // DE: Konfiguration anzeigen
        // EN: Display configuration
        $this->displayConfiguration($io, $config);

        $serverResults = [];
        $browserResults = [];
        $routeResults = [];

        // =====================================================================
        // Server-Endpoints (müssen vom Container erreichbar sein)
        // =====================================================================
        $io->section('Server Endpoints (internal)');
        $io->text('<fg=cyan>These endpoints must be reachable from the container.</>');
        $io->newLine();

        // DE: Interne Discovery URL aus Token-Endpoint ableiten
        // EN: Derive internal discovery URL from token endpoint
        $internalBaseUrl = $this->extractBaseUrl($config->tokenEndpoint);
        if ($internalBaseUrl !== null) {
            $internalDiscoveryUrl = $internalBaseUrl . '/.well-known/openid-configuration';
            $serverResults[] = $this->checkEndpoint($io, 'Discovery (internal)', $internalDiscoveryUrl, true, self::TYPE_SERVER);
        }

        // DE: JWKS Endpoint prüfen
        // EN: Check JWKS endpoint
        $serverResults[] = $this->checkEndpoint($io, 'JWKS', $config->jwksUri, true, self::TYPE_SERVER);

        // DE: Token Endpoint prüfen (nur Ping, kein Auth)
        // EN: Check Token endpoint (ping only, no auth)
        $serverResults[] = $this->checkEndpoint($io, 'Token', $config->tokenEndpoint, false, self::TYPE_SERVER);

        // DE: UserInfo Endpoint prüfen (nur Ping, kein Auth)
        // EN: Check UserInfo endpoint (ping only, no auth)
        $serverResults[] = $this->checkEndpoint($io, 'UserInfo', $config->userInfoEndpoint, false, self::TYPE_SERVER);

        // DE: Revocation Endpoint prüfen (optional)
        // EN: Check Revocation endpoint (optional)
        if ($config->revocationEndpoint !== null) {
            $serverResults[] = $this->checkEndpoint($io, 'Revocation', $config->revocationEndpoint, false, self::TYPE_SERVER);
        }

        // DE: Introspection Endpoint prüfen (optional)
        // EN: Check Introspection endpoint (optional)
        if ($config->introspectionEndpoint !== null) {
            $serverResults[] = $this->checkEndpoint($io, 'Introspection', $config->introspectionEndpoint, false, self::TYPE_SERVER);
        }

        // =====================================================================
        // Browser-Endpoints (können vom Container aus scheitern)
        // =====================================================================
        if (!$skipBrowser) {
            $io->newLine();
            $io->section('Browser Endpoints (public)');
            $io->text('<fg=yellow>These endpoints are accessed by browsers, not the container.</>');
            $io->text('<fg=yellow>Failures here may be expected if running inside Docker.</>');
            $io->newLine();

            // DE: Öffentliche Discovery URL
            // EN: Public Discovery URL
            $publicIssuer = $config->publicIssuer ?? $config->issuer;
            $publicDiscoveryUrl = rtrim($publicIssuer, '/') . '/.well-known/openid-configuration';
            $browserResults[] = $this->checkEndpoint($io, 'Discovery (public)', $publicDiscoveryUrl, true, self::TYPE_BROWSER);

            // DE: Authorization Endpoint (Browser-Redirect)
            // EN: Authorization endpoint (browser redirect)
            $browserResults[] = $this->checkEndpoint($io, 'Authorization', $config->authorizationEndpoint, false, self::TYPE_BROWSER);

            // DE: End-Session Endpoint (optional)
            // EN: End-Session endpoint (optional)
            if ($config->endSessionEndpoint !== null) {
                $browserResults[] = $this->checkEndpoint($io, 'End-Session', $config->endSessionEndpoint, false, self::TYPE_BROWSER);
            }
        }

        // =====================================================================
        // Bundle-Routen prüfen
        // =====================================================================
        if (!$skipRoutes && $this->router !== null) {
            $io->newLine();
            $io->section('Bundle Routes');
            $io->text('<fg=magenta>These routes must be registered in Symfony routing.</>');
            $io->newLine();

            $routeResults = $this->checkBundleRoutes($io);
        }

        $io->newLine();

        // =====================================================================
        // Zusammenfassung
        // =====================================================================
        return $this->displaySummary($io, $serverResults, $browserResults, $routeResults, $skipBrowser, $skipRoutes);
    }

    /**
     * DE: Zeigt die aktuelle Konfiguration an.
     * EN: Displays the current configuration.
     */
    private function displayConfiguration(SymfonyStyle $io, OidcClientConfig $config): void
    {
        $io->text(sprintf('Client ID: <info>%s</info>', $config->clientId));
        $io->text(sprintf('Issuer (public): <info>%s</info>', $config->publicIssuer ?? $config->issuer));

        $internalBaseUrl = $this->extractBaseUrl($config->tokenEndpoint);
        if ($internalBaseUrl !== null && $internalBaseUrl !== ($config->publicIssuer ?? $config->issuer)) {
            $io->text(sprintf('Issuer (internal): <info>%s</info>', $internalBaseUrl));
        }

        // DE: Optionale Endpoints anzeigen
        // EN: Show optional endpoints
        $optional = [];
        if ($config->revocationEndpoint !== null) {
            $optional[] = 'Revocation';
        }
        if ($config->introspectionEndpoint !== null) {
            $optional[] = 'Introspection';
        }
        if ($optional !== []) {
            $io->text(sprintf('Optional endpoints: <info>%s</info>', implode(', ', $optional)));
        }

        $io->newLine();
    }

    /**
     * DE: Prüft einen einzelnen Endpoint.
     * EN: Checks a single endpoint.
     *
     * @return array{name: string, url: string, success: bool, latency: float, error: ?string, type: string}
     */
    private function checkEndpoint(
        SymfonyStyle $io,
        string $name,
        string $url,
        bool $expectJson,
        string $type,
    ): array {
        $io->text(sprintf('Checking <info>%s</info>: %s', $name, $url));

        $startTime = microtime(true);
        $success = false;
        $error = null;

        try {
            $request = $this->requestFactory->createRequest('GET', $url)
                ->withHeader('Accept', $expectJson ? 'application/json' : '*/*');

            $response = $this->httpClient->sendRequest($request);
            $statusCode = $response->getStatusCode();

            // DE: Für JSON-Endpoints erwarten wir 200, für andere auch 401/405 (erreichbar aber nicht autorisiert)
            // EN: For JSON endpoints we expect 200, for others also 401/405 (reachable but not authorized)
            if ($expectJson) {
                $success = $statusCode === 200;
                if (!$success) {
                    $error = sprintf('HTTP %d', $statusCode);
                }
            } else {
                // DE: Token/UserInfo ohne Auth geben typischerweise 400/401/405 zurück
                // EN: Token/UserInfo without auth typically return 400/401/405
                $success = $statusCode < 500;
                if (!$success) {
                    $error = sprintf('HTTP %d (server error)', $statusCode);
                }
            }
        } catch (NetworkExceptionInterface $e) {
            // DE: Netzwerkfehler (DNS, Timeout, Connection refused)
            // EN: Network error (DNS, timeout, connection refused)
            $error = 'Network error: ' . $this->formatException($e);
        } catch (RequestExceptionInterface $e) {
            // DE: Request konnte nicht erstellt werden
            // EN: Request could not be created
            $error = 'Request error: ' . $this->formatException($e);
        } catch (\Throwable $e) {
            $error = 'Unexpected error: ' . $this->formatException($e);
        }

        $latency = (microtime(true) - $startTime) * 1000;

        // DE: Status-Icon ausgeben
        // EN: Output status icon
        if ($success) {
            $latencyFormatted = $this->formatLatency($latency);
            $io->text(sprintf('  <fg=green>✓</> %s', $latencyFormatted));
        } else {
            $icon = $type === self::TYPE_SERVER ? '<fg=red>✗</>' : '<fg=yellow>⚠</>';
            $io->text(sprintf('  %s %s', $icon, $error));
        }

        return [
            'name' => $name,
            'url' => $url,
            'success' => $success,
            'latency' => $latency,
            'error' => $error,
            'type' => $type,
        ];
    }

    /**
     * DE: Prüft ob Bundle-Routen registriert sind.
     * EN: Checks if bundle routes are registered.
     *
     * @return array<array{name: string, url: string, success: bool, latency: float, error: ?string, type: string}>
     */
    private function checkBundleRoutes(SymfonyStyle $io): array
    {
        $results = [];

        // DE: Liste der zu prüfenden Routen
        // EN: List of routes to check
        $routes = [
            // Core routes (required)
            OidcConstants::ROUTE_LOGIN => ['required' => true, 'label' => 'Login'],
            OidcConstants::ROUTE_CALLBACK => ['required' => true, 'label' => 'Callback'],
            OidcConstants::ROUTE_LOGOUT => ['required' => true, 'label' => 'Logout'],
            // Optional routes
            OidcConstants::ROUTE_PROFILE => ['required' => false, 'label' => 'Profile'],
            OidcConstants::ROUTE_DEBUG => ['required' => false, 'label' => 'Debug'],
            OidcConstants::ROUTE_TEST => ['required' => false, 'label' => 'Test'],
            OidcConstants::ROUTE_BACKCHANNEL_LOGOUT => ['required' => false, 'label' => 'Backchannel Logout'],
            OidcConstants::ROUTE_FRONTCHANNEL_LOGOUT => ['required' => false, 'label' => 'Frontchannel Logout'],
        ];

        foreach ($routes as $routeName => $routeConfig) {
            $result = $this->checkRoute($io, $routeName, $routeConfig['label'], $routeConfig['required']);
            if ($result !== null) {
                $results[] = $result;
            }
        }

        return $results;
    }

    /**
     * DE: Prüft eine einzelne Route.
     * EN: Checks a single route.
     *
     * @return array{name: string, url: string, success: bool, latency: float, error: ?string, type: string}|null
     */
    private function checkRoute(SymfonyStyle $io, string $routeName, string $label, bool $required): ?array
    {
        $startTime = microtime(true);

        try {
            $route = $this->router?->getRouteCollection()->get($routeName);

            if ($route === null) {
                if (!$required) {
                    // DE: Optionale Route nicht konfiguriert - kein Fehler
                    // EN: Optional route not configured - no error
                    return null;
                }

                $io->text(sprintf('Checking <info>%s</info> (%s)', $label, $routeName));
                $io->text('  <fg=red>✗</> Route not registered');

                return [
                    'name' => $label,
                    'url' => $routeName,
                    'success' => false,
                    'latency' => (microtime(true) - $startTime) * 1000,
                    'error' => 'Route not registered',
                    'type' => self::TYPE_ROUTE,
                ];
            }

            $path = $route->getPath();
            $methods = $route->getMethods() ?: ['ANY'];

            $io->text(sprintf('Checking <info>%s</info> (%s)', $label, $routeName));
            $io->text(sprintf('  <fg=green>✓</> %s [%s]', $path, implode(', ', $methods)));

            return [
                'name' => $label,
                'url' => $path,
                'success' => true,
                'latency' => (microtime(true) - $startTime) * 1000,
                'error' => null,
                'type' => self::TYPE_ROUTE,
            ];
        } catch (\Throwable $e) {
            $io->text(sprintf('Checking <info>%s</info> (%s)', $label, $routeName));
            $io->text(sprintf('  <fg=red>✗</> %s', $this->formatException($e)));

            return [
                'name' => $label,
                'url' => $routeName,
                'success' => false,
                'latency' => (microtime(true) - $startTime) * 1000,
                'error' => $this->formatException($e),
                'type' => self::TYPE_ROUTE,
            ];
        }
    }

    /**
     * DE: Zeigt die Zusammenfassung an und gibt den Exit-Code zurück.
     * EN: Displays the summary and returns the exit code.
     *
     * @param array<array{name: string, url: string, success: bool, latency: float, error: ?string, type: string}> $serverResults
     * @param array<array{name: string, url: string, success: bool, latency: float, error: ?string, type: string}> $browserResults
     * @param array<array{name: string, url: string, success: bool, latency: float, error: ?string, type: string}> $routeResults
     */
    private function displaySummary(
        SymfonyStyle $io,
        array $serverResults,
        array $browserResults,
        array $routeResults,
        bool $skipBrowser,
        bool $skipRoutes,
    ): int {
        $io->section('Summary');

        // DE: Server-Endpoints Tabelle
        // EN: Server endpoints table
        $io->text('<fg=cyan>Server Endpoints (critical)</>');
        $serverRows = [];
        $serverAllSuccess = true;

        foreach ($serverResults as $result) {
            $serverAllSuccess = $serverAllSuccess && $result['success'];
            $statusIcon = $result['success'] ? '<fg=green>OK</>' : '<fg=red>FAIL</>';
            $latencyText = $this->formatLatency($result['latency']);

            $serverRows[] = [
                $result['name'],
                $statusIcon,
                $latencyText,
                $result['error'] ?? '',
            ];
        }

        $io->table(['Endpoint', 'Status', 'Latency', 'Error'], $serverRows);

        // DE: Browser-Endpoints Tabelle (falls nicht übersprungen)
        // EN: Browser endpoints table (if not skipped)
        $browserAllSuccess = true;
        if (!$skipBrowser && $browserResults !== []) {
            $io->text('<fg=yellow>Browser Endpoints (informational)</>');
            $browserRows = [];

            foreach ($browserResults as $result) {
                $browserAllSuccess = $browserAllSuccess && $result['success'];
                $statusIcon = $result['success'] ? '<fg=green>OK</>' : '<fg=yellow>SKIP</>';
                $latencyText = $this->formatLatency($result['latency']);

                $browserRows[] = [
                    $result['name'],
                    $statusIcon,
                    $latencyText,
                    $result['error'] ?? '',
                ];
            }

            $io->table(['Endpoint', 'Status', 'Latency', 'Error'], $browserRows);

            if (!$browserAllSuccess) {
                $io->note('Browser endpoints are not reachable from the container. This is expected in Docker environments. These URLs must be accessible from the user\'s browser.');
            }
        }

        // DE: Bundle-Routen Tabelle (falls nicht übersprungen)
        // EN: Bundle routes table (if not skipped)
        $routesAllSuccess = true;
        if (!$skipRoutes && $routeResults !== []) {
            $io->text('<fg=magenta>Bundle Routes</>');
            $routeRows = [];

            foreach ($routeResults as $result) {
                $routesAllSuccess = $routesAllSuccess && $result['success'];
                $statusIcon = $result['success'] ? '<fg=green>OK</>' : '<fg=red>FAIL</>';

                $routeRows[] = [
                    $result['name'],
                    $statusIcon,
                    $result['url'],
                    $result['error'] ?? '',
                ];
            }

            $io->table(['Route', 'Status', 'Path', 'Error'], $routeRows);
        }

        // DE: Gesamtergebnis
        // EN: Overall result
        $allCriticalSuccess = $serverAllSuccess && $routesAllSuccess;

        if ($allCriticalSuccess) {
            $io->success('All server endpoints and routes are properly configured. SSO integration should work.');
            return Command::SUCCESS;
        }

        if (!$serverAllSuccess) {
            $io->error('Some server endpoints are not reachable. Please check your configuration.');
        }

        if (!$routesAllSuccess) {
            $io->error('Some bundle routes are not registered. Please check your routing configuration.');
        }

        return Command::FAILURE;
    }

    /**
     * DE: Extrahiert die Base-URL aus einem Endpoint.
     * EN: Extracts the base URL from an endpoint.
     */
    private function extractBaseUrl(string $url): ?string
    {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            return null;
        }

        $baseUrl = $parsed['scheme'] . '://' . $parsed['host'];
        if (isset($parsed['port'])) {
            $baseUrl .= ':' . $parsed['port'];
        }

        return $baseUrl;
    }

    /**
     * DE: Formatiert die Latenz mit farbiger Darstellung.
     * EN: Formats latency with colored output.
     */
    private function formatLatency(float $latencyMs): string
    {
        $formatted = sprintf('%.0f ms', $latencyMs);

        if ($latencyMs >= self::TIMEOUT_CRITICAL_MS) {
            return sprintf('<fg=red>%s</>', $formatted);
        }

        if ($latencyMs >= self::TIMEOUT_WARNING_MS) {
            return sprintf('<fg=yellow>%s</>', $formatted);
        }

        return sprintf('<fg=green>%s</>', $formatted);
    }

    /**
     * DE: Formatiert eine Exception für die Ausgabe.
     * EN: Formats an exception for output.
     */
    private function formatException(\Throwable $e): string
    {
        $message = $e->getMessage();

        // DE: Kürze lange Fehlermeldungen
        // EN: Truncate long error messages
        if (strlen($message) > 80) {
            $message = substr($message, 0, 77) . '...';
        }

        return $message;
    }
}
