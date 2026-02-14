<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\Event\OidcBackchannelLogoutEvent;
use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * DE: Controller für OpenID Connect Back-Channel Logout 1.0.
 *     Empfängt Logout-Token vom IdP und invalidiert User-Sessions.
 * EN: Controller for OpenID Connect Back-Channel Logout 1.0.
 *     Receives logout tokens from IdP and invalidates user sessions.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
final class BackchannelLogoutController extends AbstractController
{
    /**
     * DE: Der events Claim Schlüssel für Back-Channel Logout.
     * EN: The events claim key for back-channel logout.
     */
    private const LOGOUT_EVENT_KEY = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * DE: Verarbeitet Back-Channel Logout Request vom IdP.
     *     POST mit logout_token im Body (application/x-www-form-urlencoded).
     * EN: Processes back-channel logout request from IdP.
     *     POST with logout_token in body (application/x-www-form-urlencoded).
     *
     * Response codes per spec:
     * - 200: Logout successful
     * - 400: Invalid request (missing token, invalid format)
     * - 501: Not implemented (if backchannel logout not supported)
     */
    #[Route('%eurip_sso.routes.backchannel_logout%', name: OidcConstants::ROUTE_BACKCHANNEL_LOGOUT, methods: ['POST'])]
    public function backchannelLogout(Request $request): Response
    {
        // DE: Logout Token aus Request extrahieren
        // EN: Extract logout token from request
        $logoutToken = $request->request->getString('logout_token');

        if ($logoutToken === '') {
            $this->logger?->warning('Back-channel logout: missing logout_token');
            return $this->createErrorResponse('invalid_request', 'Missing logout_token parameter');
        }

        try {
            // DE: Logout Token validieren (JWT Signatur + Claims)
            // EN: Validate logout token (JWT signature + claims)
            $claims = $this->validateLogoutToken($logoutToken);

            $subject = $claims['sub'] ?? null;
            $sessionId = $claims['sid'] ?? null;
            $issuer = $claims['iss'] ?? '';

            // DE: Mindestens sub oder sid muss vorhanden sein
            // EN: At least sub or sid must be present
            if ($subject === null && $sessionId === null) {
                $this->logger?->warning('Back-channel logout: neither sub nor sid in token');
                return $this->createErrorResponse('invalid_request', 'Token must contain sub or sid claim');
            }

            $this->logger?->info('Back-channel logout received', [
                'sub' => $subject,
                'sid' => $sessionId,
                'iss' => $issuer,
            ]);

            // DE: Event dispatchen für App-spezifische Session-Invalidierung
            // EN: Dispatch event for app-specific session invalidation
            $event = new OidcBackchannelLogoutEvent(
                subject: $subject ?? '',
                sessionId: $sessionId,
                issuer: $issuer,
                claims: $claims,
            );

            $this->eventDispatcher->dispatch($event);

            if ($event->isHandled()) {
                $this->logger?->info('Back-channel logout handled by listener', [
                    'sub' => $subject,
                ]);
            } else {
                $this->logger?->notice('Back-channel logout not handled (no listener)', [
                    'sub' => $subject,
                ]);
            }

            // DE: Erfolg - auch wenn kein Listener reagiert hat (per Spec OK)
            // EN: Success - even if no listener handled it (per spec OK)
            return new Response('', Response::HTTP_OK, [
                'Cache-Control' => 'no-store',
            ]);
        } catch (ClaimsValidationException $e) {
            $this->logger?->warning('Back-channel logout: token validation failed', [
                'error' => $e->getMessage(),
                'claim' => $e->claim,
            ]);
            return $this->createErrorResponse('invalid_request', 'Token validation failed: ' . $e->getMessage());
        } catch (OidcProtocolException $e) {
            $this->logger?->warning('Back-channel logout: protocol error', [
                'error' => $e->getMessage(),
            ]);
            return $this->createErrorResponse('invalid_request', $e->getMessage());
        } catch (\Throwable $e) {
            $this->logger?->error('Back-channel logout: unexpected error', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
            ]);
            return $this->createErrorResponse('server_error', 'Internal error');
        }
    }

    /**
     * DE: Validiert das Logout Token (JWT).
     *     Prüft Signatur, Issuer, Audience und spezielle Logout-Claims.
     * EN: Validates the logout token (JWT).
     *     Checks signature, issuer, audience and special logout claims.
     *
     * @return array<string, mixed>
     * @throws OidcProtocolException
     * @throws ClaimsValidationException
     */
    private function validateLogoutToken(string $token): array
    {
        // DE: Token dekodieren mit Signaturprüfung aber ohne Nonce-Prüfung
        // EN: Decode token with signature verification but without nonce check
        $claims = $this->oidcClient->decodeIdToken(
            idToken: $token,
            verifySignature: true,
            validateClaims: true,
            expectedNonce: null,
        );

        // DE: Spezielle Logout Token Validierung per Spec
        // EN: Special logout token validation per spec

        // 1. events Claim muss vorhanden sein mit dem Logout Event Key
        $events = $claims['events'] ?? null;
        if (!is_array($events) || !array_key_exists(self::LOGOUT_EVENT_KEY, $events)) {
            throw new OidcProtocolException(
                'Invalid logout token: missing events claim with ' . self::LOGOUT_EVENT_KEY
            );
        }

        // 2. nonce darf NICHT vorhanden sein (Unterschied zu ID Token)
        if (isset($claims['nonce'])) {
            throw new OidcProtocolException('Invalid logout token: nonce must not be present');
        }

        // 3. sub oder sid muss vorhanden sein (bereits oben geprüft, aber hier nochmal für Vollständigkeit)
        if (!isset($claims['sub']) && !isset($claims['sid'])) {
            throw new OidcProtocolException('Invalid logout token: sub or sid required');
        }

        return $claims;
    }

    /**
     * DE: Erstellt eine Fehler-Response gemäß OAuth 2.0 Error Format.
     * EN: Creates an error response according to OAuth 2.0 error format.
     */
    private function createErrorResponse(string $error, string $description): Response
    {
        return new Response(
            json_encode([
                'error' => $error,
                'error_description' => $description,
            ], JSON_THROW_ON_ERROR),
            Response::HTTP_BAD_REQUEST,
            [
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
            ],
        );
    }
}
