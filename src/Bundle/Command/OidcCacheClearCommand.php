<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Bundle\Service\OidcCacheService;
use Jostkleigrewe\Sso\Client\OidcClient;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * DE: Console Command zum Leeren des OIDC Caches.
 *     Löscht Discovery-Config und JWKS Cache.
 *     Nützlich nach Secret-Änderungen oder bei Authentifizierungsproblemen.
 *
 * EN: Console command to clear the OIDC cache.
 *     Deletes discovery config and JWKS cache.
 *     Useful after secret changes or authentication issues.
 */
#[AsCommand(
    name: 'eurip:sso:cache:clear',
    description: 'Clear OIDC discovery and JWKS cache',
)]
final class OidcCacheClearCommand extends Command
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly OidcCacheService $cacheService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'discovery-only',
                null,
                InputOption::VALUE_NONE,
                'Only clear discovery cache (not JWKS)'
            )
            ->addOption(
                'jwks-only',
                null,
                InputOption::VALUE_NONE,
                'Only clear JWKS cache (not discovery)'
            )
            ->setHelp(
                <<<'HELP'
The <info>%command.name%</info> command clears the OIDC cache, including
discovery metadata and JWKS (JSON Web Key Set).

<comment>When to use:</comment>
- After changing client_secret in .env
- When getting "invalid_client" errors after secret rotation
- When OIDC provider keys have been rotated

<info>php %command.full_name%</info>

Use <info>--discovery-only</info> to only clear the discovery cache:

<info>php %command.full_name% --discovery-only</info>

Use <info>--jwks-only</info> to only clear the JWKS cache:

<info>php %command.full_name% --jwks-only</info>
HELP
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $discoveryOnly = $input->getOption('discovery-only');
        $jwksOnly = $input->getOption('jwks-only');

        $io->title('OIDC Cache Clear');

        $config = $this->oidcClient->getConfig();
        $io->text(sprintf('Issuer: <info>%s</info>', $config->issuer));

        $cleared = [];

        // DE: Discovery Cache löschen (enthält auch das clientSecret)
        // EN: Clear discovery cache (also contains clientSecret)
        if (!$jwksOnly) {
            $this->cacheService->clearDiscoveryCache();
            $cleared[] = 'Discovery config (includes client secret)';
        }

        // DE: JWKS Cache löschen
        // EN: Clear JWKS cache
        if (!$discoveryOnly) {
            $this->cacheService->clearJwksCache();
            $cleared[] = 'JWKS (JSON Web Key Set)';
        }

        $io->listing($cleared);
        $io->success('OIDC cache cleared successfully.');

        $io->note([
            'After clearing cache, the next request will fetch fresh data from the SSO provider.',
            'Run "eurip:sso:cache:warmup" to pre-populate the cache.',
        ]);

        return Command::SUCCESS;
    }
}
