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
     *     Markiert State SOFORT als verwendet um Race Conditions zu verhindern.
     * EN: Validates state and returns stored data if valid.
     *     Marks state as used IMMEDIATELY to prevent race conditions.
     *
     * @return array{nonce: string, verifier: string}|null
     */
    public function validateAndClear(string $state): ?array
    {
        $session = $this->requestStack->getSession();

        $storedState = $session->get(self::KEY_STATE);
        // DE: Type-Check für Session-Wert (könnte manipuliert sein)
        // EN: Type check for session value (could be manipulated)
        if (!is_string($storedState) || !hash_equals($storedState, $state)) {
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

        // DE: SOFORT als "used" markieren um Race Conditions zu verhindern.
        //     Bei parallelen Requests kann nur einer erfolgreich validieren.
        // EN: Mark as "used" IMMEDIATELY to prevent race conditions.
        //     With parallel requests, only one can successfully validate.
        $session->set(self::KEY_USED, true);

        return [
            'nonce' => $nonce,
            'verifier' => $verifier,
        ];
    }

    /**
     * DE: Markiert den State als verwendet (nach erfolgreichem Token-Exchange).
     *     Verhindert Replay-Attacken, erlaubt aber Retry bei Fehlern.
     * EN: Marks state as used (after successful token exchange).
     *     Prevents replay attacks but allows retry on failure.
     */
    public function markUsed(): void
    {
        $this->requestStack->getSession()->set(self::KEY_USED, true);
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
     * DE: Gibt gespeicherten State zurück, falls gültig und nicht abgelaufen.
     *     Für Wiederverwendung bei Doppelklick/Race Conditions.
     * EN: Returns stored state if valid and not expired.
     *     For reuse on double-click/race conditions.
     *
     * @return array{state: string, nonce: string, verifier: string}|null
     */
    public function getValidState(): ?array
    {
        $session = $this->requestStack->getSession();

        $state = $session->get(self::KEY_STATE);
        $nonce = $session->get(self::KEY_NONCE);
        $verifier = $session->get(self::KEY_VERIFIER);
        $expires = $session->get(self::KEY_EXPIRES);

        // DE: Alle Werte müssen vorhanden sein // EN: All values must be present
        if ($state === null || $nonce === null || $verifier === null) {
            return null;
        }

        // DE: Bereits verwendet = nicht wiederverwendbar // EN: Already used = not reusable
        if ($session->get(self::KEY_USED) === true) {
            return null;
        }

        // DE: Abgelaufen = nicht wiederverwendbar // EN: Expired = not reusable
        if ($expires !== null && time() > $expires) {
            return null;
        }

        return [
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
        ];
    }

    /**
     * DE: Debug-Info für Logging.
     * EN: Debug info for logging.
     *
     * @return array<string, mixed>
     */
    public function getDebugInfo(): array
    {
        $session = $this->requestStack->getSession();

        $state = $session->get(self::KEY_STATE);
        $expires = $session->get(self::KEY_EXPIRES);
        $used = $session->get(self::KEY_USED);

        // DE: Session-ID NICHT loggen (Security-Risiko bei Log-Leak)
        // EN: Do NOT log session ID (security risk if logs are leaked)
        return [
            'has_state' => $state !== null,
            'state_prefix' => $state !== null ? substr($state, 0, 8) . '...' : null,
            'expires_in' => $expires !== null ? max(0, $expires - time()) : null,
            'is_used' => $used === true,
        ];
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
