<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * DE: CLI-Command für Token Introspection (RFC 7662).
 *     Ermöglicht die Validierung und Inspektion von Access/Refresh Tokens.
 * EN: CLI command for token introspection (RFC 7662).
 *     Enables validation and inspection of access/refresh tokens.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 */
#[AsCommand(
    name: 'eurip:sso:introspect',
    description: 'Validate and inspect a token via Token Introspection (RFC 7662)',
)]
final class IntrospectCommand extends Command
{
    public function __construct(
        private readonly OidcClient $oidcClient,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                'token',
                InputArgument::REQUIRED,
                'The token to introspect (access_token or refresh_token)',
            )
            ->addOption(
                'type',
                null,
                InputOption::VALUE_REQUIRED,
                'Token type hint: "access_token" or "refresh_token"',
            )
            ->addOption(
                'output-json',
                'j',
                InputOption::VALUE_NONE,
                'Output introspection response as JSON',
            )
            ->setHelp(<<<'HELP'
                DE: Validiert ein Token via Token Introspection (RFC 7662).

                    Der SSO-Server prüft das Token und gibt Metadaten zurück:
                    - Ob das Token aktiv/gültig ist
                    - Welche Scopes das Token hat
                    - Für welchen Client es ausgestellt wurde
                    - Wann es abläuft

                    Typische Anwendung: Debugging, Token-Validierung prüfen.

                EN: Validates a token via Token Introspection (RFC 7662).

                    The SSO server validates the token and returns metadata:
                    - Whether the token is active/valid
                    - What scopes the token has
                    - Which client it was issued for
                    - When it expires

                    Typical usage: Debugging, verifying token validation.

                Beispiele / Examples:

                    # Token prüfen
                    php bin/console eurip:sso:introspect "eyJhbGciOiJSUzI1NiIs..."

                    # Mit Token-Type-Hint (beschleunigt Lookup)
                    php bin/console eurip:sso:introspect "eyJhbG..." --type=access_token

                    # JSON-Ausgabe
                    php bin/console eurip:sso:introspect "eyJhbG..." --output-json

                    # Token aus Variable prüfen
                    php bin/console eurip:sso:introspect "$ACCESS_TOKEN"
                HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $token = $input->getArgument('token');
        $tokenTypeHint = $input->getOption('type');
        $outputJson = $input->getOption('output-json');

        // DE: Prüfen ob Introspection Endpoint konfiguriert ist
        // EN: Check if introspection endpoint is configured
        if ($this->oidcClient->getConfig()->introspectionEndpoint === null) {
            if (!$outputJson) {
                $io->error('Token Introspection is not supported by this OIDC provider.');
                $io->note('The provider does not expose an introspection_endpoint in its discovery document.');
            }

            return Command::FAILURE;
        }

        // DE: Token-Type-Hint validieren
        // EN: Validate token type hint
        if ($tokenTypeHint !== null && !\in_array($tokenTypeHint, ['access_token', 'refresh_token'], true)) {
            if (!$outputJson) {
                $io->error('Invalid token type hint. Must be "access_token" or "refresh_token".');
            }

            return Command::FAILURE;
        }

        try {
            if (!$outputJson) {
                $io->title('Token Introspection');
                $io->writeln(sprintf(
                    '<fg=gray>Introspecting via: %s</>',
                    $this->oidcClient->getConfig()->introspectionEndpoint,
                ));
                $io->newLine();
            }

            $introspection = $this->oidcClient->introspectToken($token, $tokenTypeHint);

            // DE: JSON-Ausgabe // EN: JSON output
            if ($outputJson) {
                $data = [
                    'active' => $introspection->active,
                ];

                if ($introspection->active) {
                    $data += array_filter([
                        'scope' => $introspection->scope,
                        'client_id' => $introspection->clientId,
                        'username' => $introspection->username,
                        'sub' => $introspection->sub,
                        'token_type' => $introspection->tokenType,
                        'exp' => $introspection->exp,
                        'iat' => $introspection->iat,
                        'nbf' => $introspection->nbf,
                        'aud' => $introspection->aud,
                        'iss' => $introspection->iss,
                        'jti' => $introspection->jti,
                    ], static fn ($v) => $v !== null);
                }

                $output->writeln(json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));

                return $introspection->active ? Command::SUCCESS : Command::FAILURE;
            }

            // DE: Formatierte Ausgabe // EN: Formatted output
            if ($introspection->active) {
                $io->success('Token is ACTIVE');

                $rows = [];

                if ($introspection->clientId !== null) {
                    $rows[] = ['Client ID', $introspection->clientId];
                }
                if ($introspection->sub !== null) {
                    $rows[] = ['Subject (User ID)', $introspection->sub];
                }
                if ($introspection->username !== null) {
                    $rows[] = ['Username', $introspection->username];
                }
                if ($introspection->scope !== null) {
                    $rows[] = ['Scopes', $introspection->scope];
                }
                if ($introspection->tokenType !== null) {
                    $rows[] = ['Token Type', $introspection->tokenType];
                }
                if ($introspection->iss !== null) {
                    $rows[] = ['Issuer', $introspection->iss];
                }
                if ($introspection->aud !== null) {
                    $rows[] = ['Audience', $introspection->aud];
                }
                if ($introspection->iat !== null) {
                    $rows[] = ['Issued At', $this->formatTimestamp($introspection->iat)];
                }
                if ($introspection->exp !== null) {
                    $remaining = $introspection->getRemainingSeconds();
                    $expiresFormatted = $this->formatTimestamp($introspection->exp);

                    if ($remaining > 0) {
                        $rows[] = ['Expires At', sprintf('%s (in %ds)', $expiresFormatted, $remaining)];
                    } else {
                        $rows[] = ['Expires At', sprintf('%s (EXPIRED)', $expiresFormatted)];
                    }
                }
                if ($introspection->nbf !== null) {
                    $rows[] = ['Not Before', $this->formatTimestamp($introspection->nbf)];
                }
                if ($introspection->jti !== null) {
                    $rows[] = ['JWT ID', $introspection->jti];
                }

                $io->table(['Property', 'Value'], $rows);

                // DE: Scope-Details // EN: Scope details
                $scopes = $introspection->getScopes();
                if ($scopes !== []) {
                    $io->section('Scopes');
                    $io->listing($scopes);
                }
            } else {
                $io->warning('Token is INACTIVE');
                $io->note([
                    'The token is either:',
                    '- Expired',
                    '- Revoked',
                    '- Invalid',
                    '- Not recognized by the SSO server',
                ]);

                return Command::FAILURE;
            }

            return Command::SUCCESS;
        } catch (OidcProtocolException $e) {
            if (!$outputJson) {
                $io->error(sprintf('OIDC Protocol Error: %s', $e->getMessage()));
            }

            return Command::FAILURE;
        }
    }

    private function formatTimestamp(int $timestamp): string
    {
        return (new \DateTimeImmutable())->setTimestamp($timestamp)->format('Y-m-d H:i:s');
    }
}
