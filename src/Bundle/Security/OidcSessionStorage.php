<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Security;

use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * DE: Verwaltet OIDC Auth-State in der Session.
 *     Speichert/validiert State, Nonce und PKCE Verifier.
 *     Unterstützt Retry-Window für Race Conditions.
 * EN: Manages OIDC auth state in the session.
 *     Stores/validates state, nonce and PKCE verifier.
 *     Supports retry window for race conditions.
 */
final class OidcSessionStorage
{
    private const KEY_STATE = OidcConstants::SESSION_STATE;
    private const KEY_NONCE = OidcConstants::SESSION_NONCE;
    private const KEY_VERIFIER = OidcConstants::SESSION_VERIFIER;
    private const KEY_EXPIRES = '_eurip_sso_expires';
    private const KEY_USED = '_eurip_sso_used';

    /**
     * DE: Retry-Window in Sekunden (für Browser-Refresh, Netzwerk-Retry).
     * EN: Retry window in seconds (for browser refresh, network retry).
     */
    private const RETRY_WINDOW_SECONDS = 60;

    public function __construct(
        private readonly RequestStack $requestStack,
    ) {
    }

    /**
     * DE: Speichert Auth-State für den OIDC Flow.
     * EN: Stores authentication state for the OIDC flow.
     */
    public function store(string $state, string $nonce, string $verifier): void
    {
        $session = $this->requestStack->getSession();

        $session->set(self::KEY_STATE, $state);
        $session->set(self::KEY_NONCE, $nonce);
        $session->set(self::KEY_VERIFIER, $verifier);
        $session->set(self::KEY_EXPIRES, time() + self::RETRY_WINDOW_SECONDS);
        $session->remove(self::KEY_USED);
    }

    /**
     * DE: Validiert State und gibt gespeicherte Daten zurück.
     *     Unterstützt einmaliges Retry innerhalb des Retry-Windows.
     * EN: Validates state and returns stored data if valid.
     *     Supports single retry within the retry window.
     *
     * @return array{nonce: string, verifier: string}|null
     */
    public function validateAndClear(string $state): ?array
    {
        $session = $this->requestStack->getSession();

        $storedState = $session->get(self::KEY_STATE);
        if ($storedState === null || !hash_equals($storedState, $state)) {
            return null;
        }

        // Check if already used (prevent replay)
        if ($session->get(self::KEY_USED) === true) {
            return null;
        }

        // Check if expired
        $expires = $session->get(self::KEY_EXPIRES);
        if ($expires !== null && time() > $expires) {
            $this->clear();
            return null;
        }

        $nonce = $session->get(self::KEY_NONCE);
        $verifier = $session->get(self::KEY_VERIFIER);

        if ($nonce === null || $verifier === null) {
            return null;
        }

        // Mark as used (but don't clear yet - allows debugging)
        $session->set(self::KEY_USED, true);

        return [
            'nonce' => $nonce,
            'verifier' => $verifier,
        ];
    }

    /**
     * DE: Löscht alle gespeicherten Auth-Daten.
     * EN: Clears all stored authentication state.
     */
    public function clear(): void
    {
        $session = $this->requestStack->getSession();

        $session->remove(self::KEY_STATE);
        $session->remove(self::KEY_NONCE);
        $session->remove(self::KEY_VERIFIER);
        $session->remove(self::KEY_EXPIRES);
        $session->remove(self::KEY_USED);
    }

    /**
     * DE: Prüft ob Auth-State gespeichert ist.
     * EN: Checks if authentication state is currently stored.
     */
    public function hasState(): bool
    {
        return $this->requestStack->getSession()->has(self::KEY_STATE);
    }

    /**
     * DE: Markiert den State als erfolgreich verwendet und löscht ihn.
     *     Wird nach erfolgreichem Login aufgerufen.
     * EN: Marks state as successfully used and clears it.
     *     Called after successful login.
     */
    public function markSuccessAndClear(): void
    {
        $this->clear();
    }
}
