<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Client\OidcClient;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * DE: Console Command zum Testen der SSO-Verbindung.
 *     Prüft alle OIDC-Endpoints auf Erreichbarkeit.
 * EN: Console command to test the SSO connection.
 *     Checks all OIDC endpoints for reachability.
 */
#[AsCommand(
    name: 'eurip:sso:test-connection',
    description: 'Test connectivity to SSO server endpoints',
)]
final class OidcTestConnectionCommand extends Command
{
    private const TIMEOUT_WARNING_MS = 1000;
    private const TIMEOUT_CRITICAL_MS = 3000;

    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'timeout',
                't',
                InputOption::VALUE_REQUIRED,
                'Connection timeout in seconds',
                '10'
            )
            ->setHelp(
                <<<'HELP'
The <info>%command.name%</info> command tests connectivity to all SSO server endpoints.

It checks:
  - Discovery endpoint (OpenID Configuration)
  - JWKS endpoint (JSON Web Key Set)
  - Token endpoint (reachability only)
  - UserInfo endpoint (reachability only)

<info>php %command.full_name%</info>

Returns exit code 0 if all endpoints are reachable, 1 otherwise.
HELP
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('SSO Connection Test');

        $config = $this->oidcClient->getConfig();
        $io->text(sprintf('Issuer: <info>%s</info>', $config->issuer));
        $io->text(sprintf('Client ID: <info>%s</info>', $config->clientId));
        $io->newLine();

        $results = [];
        $allSuccess = true;

        // DE: Discovery Endpoint prüfen
        // EN: Check Discovery endpoint
        $discoveryUrl = rtrim($config->issuer, '/') . '/.well-known/openid-configuration';
        $results[] = $this->checkEndpoint($io, 'Discovery', $discoveryUrl, true);

        // DE: JWKS Endpoint prüfen
        // EN: Check JWKS endpoint
        $results[] = $this->checkEndpoint($io, 'JWKS', $config->jwksUri, true);

        // DE: Token Endpoint prüfen (nur Ping, kein Auth)
        // EN: Check Token endpoint (ping only, no auth)
        $results[] = $this->checkEndpoint($io, 'Token', $config->tokenEndpoint, false);

        // DE: UserInfo Endpoint prüfen (nur Ping, kein Auth)
        // EN: Check UserInfo endpoint (ping only, no auth)
        $results[] = $this->checkEndpoint($io, 'UserInfo', $config->userInfoEndpoint, false);

        // DE: End-Session Endpoint prüfen (optional)
        // EN: Check End-Session endpoint (optional)
        if ($config->endSessionEndpoint !== null) {
            $results[] = $this->checkEndpoint($io, 'End-Session', $config->endSessionEndpoint, false);
        }

        $io->newLine();

        // DE: Zusammenfassung
        // EN: Summary
        $io->section('Summary');

        $rows = [];
        foreach ($results as $result) {
            $allSuccess = $allSuccess && $result['success'];

            $statusIcon = $result['success'] ? '<fg=green>OK</>' : '<fg=red>FAIL</>';
            $latencyText = $this->formatLatency($result['latency']);

            $rows[] = [
                $result['name'],
                $statusIcon,
                $latencyText,
                $result['error'] ?? '',
            ];
        }

        $io->table(
            ['Endpoint', 'Status', 'Latency', 'Error'],
            $rows
        );

        if ($allSuccess) {
            $io->success('All endpoints are reachable.');
            return Command::SUCCESS;
        }

        $io->error('Some endpoints are not reachable.');
        return Command::FAILURE;
    }

    /**
     * DE: Prüft einen einzelnen Endpoint.
     * EN: Checks a single endpoint.
     *
     * @return array{name: string, url: string, success: bool, latency: float, error: ?string}
     */
    private function checkEndpoint(
        SymfonyStyle $io,
        string $name,
        string $url,
        bool $expectJson,
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
        } catch (\Throwable $e) {
            $error = $this->formatException($e);
        }

        $latency = (microtime(true) - $startTime) * 1000;

        // DE: Status-Icon ausgeben
        // EN: Output status icon
        if ($success) {
            $latencyFormatted = $this->formatLatency($latency);
            $io->text(sprintf('  <fg=green>✓</> %s', $latencyFormatted));
        } else {
            $io->text(sprintf('  <fg=red>✗</> %s', $error));
        }

        return [
            'name' => $name,
            'url' => $url,
            'success' => $success,
            'latency' => $latency,
            'error' => $error,
        ];
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
