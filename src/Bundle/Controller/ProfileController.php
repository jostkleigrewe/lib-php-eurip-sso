<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;

/**
 * DE: Controller für User-Profil-Seite.
 * EN: Controller for user profile page.
 */
final class ProfileController extends AbstractController
{
    public function __construct(
        private readonly string $loginPath = '/auth/login',
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

        return $this->render('@EuripSso/profile.html.twig', [
            'user' => $user,
            'login_path' => $this->loginPath,
            'logout_route' => 'eurip_sso_logout',
        ]);
    }
}
