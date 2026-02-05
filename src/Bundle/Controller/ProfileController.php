<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Bundle\Service\EuripSsoClaimsService;
use Jostkleigrewe\Sso\Bundle\Service\EuripSsoTokenStorage;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;

/**
 * DE: Controller für User-Profil-Seite.
 *     Zeigt detaillierte Informationen über den authentifizierten User.
 * EN: Controller for user profile page.
 *     Shows detailed information about the authenticated user.
 */
final class ProfileController extends AbstractController
{
    public function __construct(
        private readonly string $loginPath = '/auth/login',
        private readonly ?EuripSsoClaimsService $claimsService = null,
        private readonly ?EuripSsoTokenStorage $tokenStorage = null,
    ) {
    }

    /**
     * DE: Zeigt das User-Profil mit OIDC Claims.
     * EN: Shows user profile with OIDC claims.
     */
    public function profile(): Response
    {
        $user = $this->getUser();

        if ($user === null) {
            return $this->redirect($this->loginPath);
        }

        // DE: Basis-Daten für Template
        // EN: Base data for template
        $templateData = [
            'user' => $user,
            'login_path' => $this->loginPath,
            'logout_route' => 'eurip_sso_logout',
        ];

        // DE: Claims-Daten hinzufügen (wenn Client-Services verfügbar)
        // EN: Add claims data (if client services available)
        if ($this->claimsService !== null) {
            $claims = $this->claimsService->getClaimsOrNull();

            $templateData['claims'] = $claims?->all() ?? [];
            $templateData['global_roles'] = $claims?->getRoles() ?? [];
            $templateData['client_roles'] = $claims?->getClientRoles() ?? [];
            $templateData['permissions'] = $claims?->getClientPermissions() ?? [];
            $templateData['groups'] = $claims?->getClientGroups() ?? [];
            $templateData['is_blocked'] = $claims?->isBlocked() ?? false;
        }

        // DE: Token-Status hinzufügen (wenn Client-Services verfügbar)
        // EN: Add token status (if client services available)
        if ($this->tokenStorage !== null) {
            $expiresAt = $this->tokenStorage->getExpiresAt();
            $templateData['token_expires_at'] = $expiresAt;
            $templateData['token_is_valid'] = $this->tokenStorage->hasValidAccessToken();
            $templateData['token_expires_soon'] = $this->tokenStorage->isAccessTokenExpiringSoon(300);
            $templateData['has_refresh_token'] = $this->tokenStorage->canRefresh();

            // DE: Verbleibende Zeit berechnen
            // EN: Calculate remaining time
            if ($expiresAt !== null) {
                $now = new \DateTimeImmutable();
                $diff = $expiresAt->getTimestamp() - $now->getTimestamp();
                $templateData['token_remaining_seconds'] = max(0, $diff);
            }
        }

        // DE: Flag ob erweiterte Informationen verfügbar sind
        // EN: Flag if extended information is available
        $templateData['has_extended_info'] = $this->claimsService !== null;

        return $this->render('@EuripSso/profile.html.twig', $templateData);
    }
}
