<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Command;

use Jostkleigrewe\Sso\Client\OidcClient;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * DE: Console Command zum Aufwärmen des OIDC Caches.
 *     Lädt Discovery und JWKS vor, um HTTP-Requests beim ersten Login zu vermeiden.
 * EN: Console command to warm up the OIDC cache.
 *     Preloads discovery and JWKS to avoid HTTP requests on first login.
 */
#[AsCommand(
    name: 'eurip:sso:cache:warmup',
    description: 'Warm up OIDC discovery and JWKS cache',
)]
final class OidcCacheWarmupCommand extends Command
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly ?CacheItemPoolInterface $cache = null,
        private readonly int $cacheTtl = 3600,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Force refresh even if cache is valid'
            )
            ->addOption(
                'jwks-only',
                null,
                InputOption::VALUE_NONE,
                'Only warm up JWKS cache'
            )
            ->setHelp(
                <<<'HELP'
The <info>%command.name%</info> command warms up the OIDC cache by preloading
discovery metadata and JWKS (JSON Web Key Set) from the identity provider.

This eliminates HTTP requests on the first user login, improving performance.

<info>php %command.full_name%</info>

Use <info>--force</info> to refresh the cache even if it's still valid:

<info>php %command.full_name% --force</info>

Use <info>--jwks-only</info> to only warm up the JWKS cache:

<info>php %command.full_name% --jwks-only</info>
HELP
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $force = $input->getOption('force');
        $jwksOnly = $input->getOption('jwks-only');

        $io->title('OIDC Cache Warmup');

        try {
            $config = $this->oidcClient->getConfig();
            $io->text(sprintf('Issuer: <info>%s</info>', $config->issuer));

            // Check if already cached (unless force)
            if (!$force && $this->oidcClient->hasJwksLoaded()) {
                $io->success('JWKS already loaded in memory.');
                return Command::SUCCESS;
            }

            // Warm up JWKS
            $io->section('Fetching JWKS');
            $io->text(sprintf('JWKS URI: <info>%s</info>', $config->jwksUri));

            $startTime = microtime(true);
            $jwks = $this->oidcClient->fetchAndCacheJwks();
            $duration = round((microtime(true) - $startTime) * 1000);

            $keyCount = count($jwks['keys'] ?? []);
            $io->text(sprintf('Loaded <info>%d</info> keys in <info>%d ms</info>', $keyCount, $duration));

            // Cache JWKS if cache pool is available
            if ($this->cache !== null) {
                $cacheKey = 'eurip_sso.jwks.' . md5($config->jwksUri);
                $cacheItem = $this->cache->getItem($cacheKey);
                $cacheItem->set($jwks);
                $cacheItem->expiresAfter($this->cacheTtl);
                $this->cache->save($cacheItem);
                $io->text(sprintf('Cached with TTL: <info>%d seconds</info>', $this->cacheTtl));
            }

            // Display endpoints info
            if (!$jwksOnly) {
                $io->section('OIDC Endpoints');
                $io->table(
                    ['Endpoint', 'URL'],
                    [
                        ['Authorization', $config->authorizationEndpoint],
                        ['Token', $config->tokenEndpoint],
                        ['UserInfo', $config->userInfoEndpoint],
                        ['JWKS', $config->jwksUri],
                        ['End Session', $config->endSessionEndpoint ?? '(not configured)'],
                    ]
                );
            }

            $io->success('OIDC cache warmed up successfully.');

            return Command::SUCCESS;
        } catch (\Throwable $e) {
            $io->error(sprintf('Cache warmup failed: %s', $e->getMessage()));

            if ($output->isVerbose()) {
                $io->text($e->getTraceAsString());
            }

            return Command::FAILURE;
        }
    }
}
