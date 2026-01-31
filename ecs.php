<?php

declare(strict_types=1);

use PhpCsFixer\Fixer\Import\NoUnusedImportsFixer;
use PhpCsFixer\Fixer\Import\OrderedImportsFixer;
use PhpCsFixer\Fixer\Operator\NotOperatorWithSuccessorSpaceFixer;
use Symplify\EasyCodingStandard\Config\ECSConfig;

return ECSConfig::configure()
    ->withPaths([
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->withRootFiles()
    ->withPreparedSets(
        psr12: true,
        strict: true,
        cleanCode: true,
    )
    ->withRules([
        NoUnusedImportsFixer::class,
        OrderedImportsFixer::class,
    ])
    ->withSkip([
        // Don't require space after not operator (allow !$var)
        NotOperatorWithSuccessorSpaceFixer::class,
    ]);
