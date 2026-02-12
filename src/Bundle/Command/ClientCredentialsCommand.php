<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * DE: CLI-Command für Client Credentials Grant (RFC 6749 §4.4).
 *     Ermöglicht das Abrufen eines Access Tokens für Machine-to-Machine Kommunikation.
 * EN: CLI command for client credentials grant (RFC 6749 §4.4).
 *     Enables fetching an access token for machine-to-machine communication.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
#[AsCommand(
    name: 'eurip:sso:client-credentials',
    description: 'Get access token via Client Credentials Grant (RFC 6749) - for M2M authentication',
)]
final class ClientCredentialsCommand extends Command
{
    public function __construct(
        private readonly OidcClient $oidcClient,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'scopes',
                's',
                InputOption::VALUE_REQUIRED,
                'Scopes to request (comma-separated)',
                '',
            )
            ->addOption(
                'output-token',
                't',
                InputOption::VALUE_NONE,
                'Output only the access token (for piping to other commands)',
            )
            ->addOption(
                'output-json',
                'j',
                InputOption::VALUE_NONE,
                'Output full token response as JSON',
            )
            ->setHelp(<<<'HELP'
                DE: Holt einen Access Token via Client Credentials Grant (RFC 6749 §4.4).

                    Dieser Grant Type ist für Machine-to-Machine (M2M) Kommunikation gedacht,
                    bei der kein Benutzer involviert ist. Typische Anwendungsfälle:

                    - Cronjobs, die APIs aufrufen
                    - Microservices, die miteinander kommunizieren
                    - Backend-Integrationen

                    Voraussetzung: Ein Client Secret muss konfiguriert sein.

                EN: Fetches an access token via Client Credentials Grant (RFC 6749 §4.4).

                    This grant type is intended for machine-to-machine (M2M) communication
                    where no user is involved. Typical use cases:

                    - Cronjobs calling APIs
                    - Microservices communicating with each other
                    - Backend integrations

                    Prerequisite: A client secret must be configured.

                Beispiele / Examples:

                    # Token abrufen und Details anzeigen
                    php bin/console eurip:sso:client-credentials

                    # Mit Scopes
                    php bin/console eurip:sso:client-credentials --scopes="api:read,api:write"

                    # Nur Token ausgeben (für Scripting)
                    TOKEN=$(php bin/console eurip:sso:client-credentials --output-token)
                    curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data

                    # JSON-Ausgabe
                    php bin/console eurip:sso:client-credentials --output-json
                HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $outputToken = $input->getOption('output-token');
        $outputJson = $input->getOption('output-json');

        // DE: Scopes parsen // EN: Parse scopes
        $scopesString = $input->getOption('scopes');
        $scopes = $scopesString !== '' ? array_map('trim', explode(',', $scopesString)) : [];

        // DE: Prüfen ob Client Secret konfiguriert ist
        // EN: Check if client secret is configured
        if ($this->oidcClient->getConfig()->clientSecret === null) {
            if (!$outputToken && !$outputJson) {
                $io->error('Client Credentials Grant requires a client_secret.');
                $io->note('Configure the client_secret in your eurip_sso.yaml configuration.');
            }

            return Command::FAILURE;
        }

        try {
            // DE: Token anfordern // EN: Request token
            if (!$outputToken && !$outputJson) {
                $io->title('Client Credentials Grant');
                $io->writeln(sprintf(
                    '<fg=gray>Requesting token from: %s</>',
                    $this->oidcClient->getConfig()->tokenEndpoint,
                ));
                $io->newLine();
            }

            $tokenResponse = $this->oidcClient->getClientCredentialsToken($scopes);

            // DE: Ausgabe je nach Modus // EN: Output depending on mode
            if ($outputJson) {
                $output->writeln(json_encode([
                    'access_token' => $tokenResponse->accessToken,
                    'token_type' => $tokenResponse->tokenType,
                    'expires_in' => $tokenResponse->expiresIn,
                    'scope' => $tokenResponse->scope,
                ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            } elseif ($outputToken) {
                $output->writeln($tokenResponse->accessToken);
            } else {
                $io->success('Token obtained successfully!');

                $io->table(
                    ['Property', 'Value'],
                    [
                        ['Token Type', $tokenResponse->tokenType],
                        ['Expires In', sprintf('%d seconds', $tokenResponse->expiresIn)],
                        ['Expires At', $tokenResponse->expiresAt->format('Y-m-d H:i:s')],
                        ['Scopes', $tokenResponse->scope ?? '(none requested)'],
                    ],
                );

                // DE: Token-Preview (erste 50 Zeichen)
                // EN: Token preview (first 50 characters)
                $tokenPreview = substr($tokenResponse->accessToken, 0, 50) . '...';
                $io->writeln(sprintf('<fg=gray>Token (preview): %s</>', $tokenPreview));
                $io->newLine();
                $io->note('Use --output-token to get the full token for scripting.');
            }

            return Command::SUCCESS;
        } catch (OidcProtocolException $e) {
            if (!$outputToken && !$outputJson) {
                $io->error(sprintf('OIDC Protocol Error: %s', $e->getMessage()));
            }

            return Command::FAILURE;
        } catch (TokenExchangeFailedException $e) {
            if (!$outputToken && !$outputJson) {
                $io->error(sprintf('Token request failed: %s - %s', $e->error, $e->errorDescription));

                if ($e->error === 'invalid_client') {
                    $io->note('Check that your client_id and client_secret are correct.');
                } elseif ($e->error === 'invalid_scope') {
                    $io->note('One or more requested scopes are not allowed for this client.');
                } elseif ($e->error === 'unauthorized_client') {
                    $io->note('This client is not authorized for the client_credentials grant type.');
                }
            }

            return Command::FAILURE;
        }
    }
}
