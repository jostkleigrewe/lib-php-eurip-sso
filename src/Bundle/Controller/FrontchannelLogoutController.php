<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\Event\OidcFrontchannelLogoutEvent;
use Jostkleigrewe\Sso\Bundle\OidcConstants;
use Jostkleigrewe\Sso\Client\OidcClient;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * DE: Controller für OpenID Connect Front-Channel Logout 1.0.
 *     Wird vom IdP via Iframe aufgerufen um lokale Sessions zu invalidieren.
 * EN: Controller for OpenID Connect Front-Channel Logout 1.0.
 *     Called by IdP via iframe to invalidate local sessions.
 *
 * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html
 */
final class FrontchannelLogoutController extends AbstractController
{
    public function __construct(
        private readonly OidcClient $oidcClient,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * DE: Verarbeitet Front-Channel Logout Request vom IdP.
     *     GET mit optionalen Query-Parametern: iss, sid.
     *     Response muss in Iframe anzeigbar sein (keine X-Frame-Options).
     * EN: Processes front-channel logout request from IdP.
     *     GET with optional query params: iss, sid.
     *     Response must be displayable in iframe (no X-Frame-Options).
     */
    #[Route('%eurip_sso.routes.frontchannel_logout%', name: OidcConstants::ROUTE_FRONTCHANNEL_LOGOUT, methods: ['GET'])]
    public function frontchannelLogout(Request $request): Response
    {
        // DE: Parameter aus Query-String extrahieren
        // EN: Extract parameters from query string
        $issuer = $request->query->getString('iss', '');
        $sessionId = $request->query->getString('sid');

        if ($sessionId === '') {
            $sessionId = null;
        }

        // DE: Issuer validieren (wenn vorhanden)
        // EN: Validate issuer (if present)
        $config = $this->oidcClient->getConfig();

        if ($issuer !== '') {
            $validIssuers = [$config->issuer];
            if ($config->publicIssuer !== null) {
                $validIssuers[] = $config->publicIssuer;
            }

            if (!in_array($issuer, $validIssuers, true)) {
                $this->logger?->warning('Front-channel logout: invalid issuer', [
                    'expected' => $validIssuers,
                    'actual' => $issuer,
                ]);

                return $this->createIframeResponse('Invalid issuer', Response::HTTP_BAD_REQUEST);
            }
        }

        $this->logger?->info('Front-channel logout received', [
            'iss' => $issuer,
            'sid' => $sessionId,
        ]);

        // DE: Event dispatchen für App-spezifische Logout-Logik
        // EN: Dispatch event for app-specific logout logic
        $event = new OidcFrontchannelLogoutEvent(
            issuer: $issuer !== '' ? $issuer : $config->issuer,
            sessionId: $sessionId,
        );

        $this->eventDispatcher->dispatch($event);

        // DE: Lokale Session invalidieren
        // EN: Invalidate local session
        $session = $request->getSession();

        // DE: Security Token löschen
        // EN: Clear security token
        $this->tokenStorage->setToken(null);

        // DE: Session invalidieren
        // EN: Invalidate session
        $session->invalidate();

        if ($event->isHandled()) {
            $this->logger?->info('Front-channel logout handled by listener');
        }

        $this->logger?->info('Front-channel logout completed');

        // DE: Leere HTML-Response für Iframe (keine Redirect-Header!)
        // EN: Empty HTML response for iframe (no redirect headers!)
        return $this->createIframeResponse('Logged out');
    }

    /**
     * DE: Erstellt eine Iframe-kompatible Response.
     *     Wichtig: Keine X-Frame-Options Header, damit IdP den Iframe laden kann.
     * EN: Creates an iframe-compatible response.
     *     Important: No X-Frame-Options header, so IdP can load the iframe.
     */
    private function createIframeResponse(string $message, int $statusCode = Response::HTTP_OK): Response
    {
        // DE: Minimale HTML-Response (wird in verstecktem Iframe geladen)
        // EN: Minimal HTML response (loaded in hidden iframe)
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head><title>Logout</title></head>
<body>{$message}</body>
</html>
HTML;

        return new Response($html, $statusCode, [
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
            // DE: KEIN X-Frame-Options - Iframe muss ladbar sein!
            // EN: NO X-Frame-Options - iframe must be loadable!
        ]);
    }
}
