<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\DTO\DeviceCodeResponse;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * DE: CLI-Command für Device Authorization Grant (RFC 8628).
 *     Ermöglicht Login über CLI ohne Browser auf dem gleichen Gerät.
 * EN: CLI command for device authorization grant (RFC 8628).
 *     Enables login via CLI without browser on the same device.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
#[AsCommand(
    name: 'eurip:sso:device-login',
    description: 'Authenticate via Device Code Flow (RFC 8628) - for CLI applications',
)]
final class DeviceLoginCommand extends Command
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
                'openid,profile,email',
            )
            ->addOption(
                'output-token',
                't',
                InputOption::VALUE_NONE,
                'Output the access token on success (for piping to other commands)',
            )
            ->addOption(
                'output-json',
                'j',
                InputOption::VALUE_NONE,
                'Output full token response as JSON',
            )
            ->setHelp(<<<'HELP'
                DE: Authentifiziert über Device Code Flow (RFC 8628).

                    1. Command startet und zeigt einen User-Code an
                    2. Öffne die angezeigte URL im Browser (auf beliebigem Gerät)
                    3. Gib den User-Code ein und autorisiere
                    4. Das CLI erhält automatisch die Tokens

                EN: Authenticates via Device Code Flow (RFC 8628).

                    1. Command starts and displays a user code
                    2. Open the displayed URL in a browser (on any device)
                    3. Enter the user code and authorize
                    4. The CLI automatically receives the tokens

                Beispiele / Examples:

                    # Standard-Login
                    php bin/console eurip:sso:device-login

                    # Mit zusätzlichen Scopes
                    php bin/console eurip:sso:device-login --scopes="openid,profile,email,roles"

                    # Access Token für Pipe ausgeben
                    php bin/console eurip:sso:device-login --output-token

                    # Volle Token-Response als JSON
                    php bin/console eurip:sso:device-login --output-json
                HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $outputToken = $input->getOption('output-token');
        $outputJson = $input->getOption('output-json');

        // DE: Scopes parsen // EN: Parse scopes
        $scopesString = $input->getOption('scopes');
        $scopes = array_map('trim', explode(',', $scopesString));

        // DE: Prüfen ob Device Code Flow unterstützt wird
        // EN: Check if device code flow is supported
        if ($this->oidcClient->getConfig()->deviceAuthorizationEndpoint === null) {
            $io->error('Device Code Flow is not supported by this OIDC provider.');
            $io->note('The provider does not expose a device_authorization_endpoint in its discovery document.');

            return Command::FAILURE;
        }

        try {
            // DE: Device Code anfordern // EN: Request device code
            $deviceCode = $this->oidcClient->requestDeviceCode($scopes);

            $this->displayInstructions($io, $deviceCode);

            // DE: Polling starten // EN: Start polling
            $tokenResponse = $this->oidcClient->awaitDeviceToken(
                $deviceCode,
                fn (int $attempt, int $interval) => $this->onPoll($io, $attempt, $interval, $outputToken || $outputJson),
            );

            // DE: Erfolg! // EN: Success!
            if (!$outputToken && !$outputJson) {
                $io->newLine();
                $io->success('Authentication successful!');

                $io->table(
                    ['Property', 'Value'],
                    [
                        ['Token Type', $tokenResponse->tokenType],
                        ['Expires In', sprintf('%d seconds', $tokenResponse->expiresIn)],
                        ['Scopes', $tokenResponse->scope ?? implode(' ', $scopes)],
                        ['Has Refresh Token', $tokenResponse->canRefresh() ? 'Yes' : 'No'],
                        ['Has ID Token', $tokenResponse->idToken !== null ? 'Yes' : 'No'],
                    ],
                );

                $io->note('Tokens are not persisted. Use --output-token or --output-json to capture them.');
            } elseif ($outputJson) {
                // DE: JSON-Output für Scripting // EN: JSON output for scripting
                $output->writeln(json_encode([
                    'access_token' => $tokenResponse->accessToken,
                    'token_type' => $tokenResponse->tokenType,
                    'expires_in' => $tokenResponse->expiresIn,
                    'refresh_token' => $tokenResponse->refreshToken,
                    'id_token' => $tokenResponse->idToken,
                    'scope' => $tokenResponse->scope,
                ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            } else {
                // DE: Nur Access Token ausgeben // EN: Only output access token
                $output->writeln($tokenResponse->accessToken);
            }

            return Command::SUCCESS;
        } catch (OidcProtocolException $e) {
            $io->error(sprintf('OIDC Protocol Error: %s', $e->getMessage()));

            return Command::FAILURE;
        } catch (TokenExchangeFailedException $e) {
            $io->newLine();

            if ($e->error === 'access_denied') {
                $io->warning('Authorization was denied by the user.');
            } elseif ($e->error === 'expired_token') {
                $io->warning('The device code has expired. Please try again.');
            } else {
                $io->error(sprintf('Token exchange failed: %s', $e->getMessage()));
            }

            return Command::FAILURE;
        }
    }

    private function displayInstructions(SymfonyStyle $io, DeviceCodeResponse $deviceCode): void
    {
        $io->title('Device Authorization');

        $io->block(
            'To sign in, open the following URL in your browser:',
            null,
            'fg=white;bg=blue',
            ' ',
            true,
        );

        $io->newLine();
        $io->writeln(sprintf('  <href=%s>%s</>', $deviceCode->verificationUri, $deviceCode->verificationUri));
        $io->newLine();

        $io->block(
            sprintf('Enter this code: %s', $deviceCode->getFormattedUserCode()),
            null,
            'fg=black;bg=yellow',
            ' ',
            true,
        );

        $io->newLine();

        // DE: Wenn verification_uri_complete verfügbar, zusätzlich anzeigen
        // EN: If verification_uri_complete available, show additionally
        if ($deviceCode->verificationUriComplete !== null) {
            $io->note(sprintf(
                'Or open this URL directly (code pre-filled): %s',
                $deviceCode->verificationUriComplete,
            ));
        }

        $io->writeln(sprintf(
            '<fg=gray>Code expires in %d seconds. Polling every %d seconds...</>',
            $deviceCode->expiresIn,
            $deviceCode->interval,
        ));

        $io->newLine();
        $io->write('Waiting for authorization');
    }

    private function onPoll(SymfonyStyle $io, int $attempt, int $interval, bool $quiet): void
    {
        if ($quiet) {
            return;
        }

        // DE: Fortschrittsanzeige mit Punkten // EN: Progress indicator with dots
        $io->write('.');

        // DE: Zeilenumbruch alle 60 Punkte // EN: Line break every 60 dots
        if ($attempt % 60 === 0) {
            $io->newLine();
            $io->write('Waiting for authorization');
        }
    }
}
