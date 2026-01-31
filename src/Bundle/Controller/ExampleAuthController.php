<?php

declare(strict_types=1);

namespace Jostkleigrewe\Sso\Bundle\Controller;

use Jostkleigrewe\Sso\Client\OidcClient;
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * DE: BEISPIEL-CONTROLLER - Kopiere und passe an.
 *     Zeigt den kompletten OIDC Login Flow: login, callback, logout.
 * EN: EXAMPLE CONTROLLER - Copy and customize.
 *     Shows the complete OIDC login flow: login, callback, logout.
 *
 * Usage: Copy to src/Controller/AuthController.php, adjust namespace.
 */
class ExampleAuthController extends AbstractController
{
    private const SESSION_STATE = '_sso_state';
    private const SESSION_NONCE = '_sso_nonce';
    private const SESSION_VERIFIER = '_sso_verifier';

    public function __construct(
        private readonly OidcClient $oidcClient,
    ) {
    }

    /**
     * Step 1: Login starten - Redirect zum SSO.
     *
     * #[Route('/auth/login', name: 'app_auth_login')]
     */
    public function login(Request $request): RedirectResponse
    {
        // Optional: Bereits eingeloggt?
        if ($this->getUser() !== null) {
            return $this->redirectToRoute('app_home');
        }

        // Authorization URL mit PKCE erstellen
        $authData = $this->oidcClient->buildAuthorizationUrl([
            'openid',
            'profile',
            'email',
        ]);

        // State, Nonce und Verifier in Session speichern
        $session = $request->getSession();
        $session->set(self::SESSION_STATE, $authData['state']);
        $session->set(self::SESSION_NONCE, $authData['nonce']);
        $session->set(self::SESSION_VERIFIER, $authData['code_verifier']);

        // Optional: Return-URL speichern
        $returnUrl = $request->query->get('return');
        if ($returnUrl !== null) {
            $session->set('_auth_return_url', $returnUrl);
        }

        // Redirect zum SSO
        return new RedirectResponse($authData['url']);
    }

    /**
     * Step 2: Callback vom SSO verarbeiten.
     *
     * #[Route('/auth/callback', name: 'app_auth_callback')]
     */
    public function callback(Request $request): Response
    {
        $session = $request->getSession();

        // Error vom SSO?
        if ($request->query->has('error')) {
            $error = $request->query->getString('error');
            $description = $request->query->getString('error_description', 'Login fehlgeschlagen');

            $this->addFlash('error', $description);

            return $this->redirectToRoute('app_login');
        }

        // Code und State aus Query
        $code = $request->query->getString('code');
        $state = $request->query->getString('state');

        if ($code === '' || $state === '') {
            $this->addFlash('error', 'Ungueltige Callback-Parameter');

            return $this->redirectToRoute('app_login');
        }

        // State validieren (CSRF-Schutz)
        $expectedState = $session->get(self::SESSION_STATE);
        if ($state !== $expectedState) {
            $this->addFlash('error', 'Ungueltige Session (State mismatch)');

            return $this->redirectToRoute('app_login');
        }

        // Code Verifier aus Session
        $codeVerifier = $session->get(self::SESSION_VERIFIER);
        if ($codeVerifier === null) {
            $this->addFlash('error', 'Ungueltige Session (Verifier fehlt)');

            return $this->redirectToRoute('app_login');
        }

        // Session-Daten bereinigen
        $session->remove(self::SESSION_STATE);
        $session->remove(self::SESSION_NONCE);
        $session->remove(self::SESSION_VERIFIER);

        try {
            // Code gegen Tokens tauschen
            $tokens = $this->oidcClient->exchangeCode($code, $codeVerifier);

            // ID Token dekodieren fuer User-Daten
            $claims = [];
            if ($tokens->idToken !== null) {
                $claims = $this->oidcClient->decodeIdToken($tokens->idToken);
            }

            // Optional: UserInfo abrufen fuer zusaetzliche Claims
            // $userInfo = $this->oidcClient->getUserInfo($tokens->accessToken);

            // === HIER DEINE USER-LOGIK ===
            $this->handleSuccessfulLogin($tokens, $claims, $request);

            // Return-URL oder Default
            $returnUrl = $session->get('_auth_return_url', '/');
            $session->remove('_auth_return_url');

            return $this->redirect($returnUrl);
        } catch (TokenExchangeFailedException $e) {
            $this->addFlash('error', 'Login fehlgeschlagen: ' . $e->errorDescription);

            return $this->redirectToRoute('app_login');
        }
    }

    /**
     * Step 3: Logout.
     *
     * #[Route('/auth/logout', name: 'app_auth_logout')]
     */
    public function logout(Request $request): RedirectResponse
    {
        // Session beenden
        $request->getSession()->invalidate();

        // Optional: Redirect zum SSO Logout (end_session_endpoint)
        // $logoutUrl = $this->oidcClient->getConfig()->endSessionEndpoint;
        // return new RedirectResponse($logoutUrl . '?post_logout_redirect_uri=' . urlencode($homeUrl));

        $this->addFlash('success', 'Erfolgreich abgemeldet');

        return $this->redirectToRoute('app_login');
    }

    /**
     * Verarbeite erfolgreichen Login.
     *
     * PASSE DIESE METHODE AN DEINE APP AN:
     * - User in DB suchen oder erstellen
     * - Symfony Security Token setzen
     * - Tokens speichern (fuer API-Calls)
     *
     * @param \Jostkleigrewe\Sso\Contracts\DTO\TokenResponse $tokens
     * @param array<string, mixed> $claims ID Token Claims
     */
    private function handleSuccessfulLogin($tokens, array $claims, Request $request): void
    {
        // Beispiel: User-Daten aus Claims
        $sub = $claims['sub'] ?? null;        // Eindeutige User-ID vom SSO
        $email = $claims['email'] ?? null;    // E-Mail
        $name = $claims['name'] ?? null;      // Name

        // === BEISPIEL: User in DB suchen/erstellen ===
        //
        // $user = $this->userRepository->findOneBy(['ssoSub' => $sub]);
        //
        // if ($user === null) {
        //     // Neuen User erstellen
        //     $user = new User();
        //     $user->setSsoSub($sub);
        //     $user->setEmail($email);
        //     $user->setName($name);
        //     $this->entityManager->persist($user);
        //     $this->entityManager->flush();
        // }

        // === BEISPIEL: Symfony Security Token setzen ===
        //
        // $token = new UsernamePasswordToken($user, 'main', $user->getRoles());
        // $this->container->get('security.token_storage')->setToken($token);
        // $request->getSession()->set('_security_main', serialize($token));

        // === BEISPIEL: Tokens in Session speichern (fuer API-Calls) ===
        //
        // $request->getSession()->set('_sso_access_token', $tokens->accessToken);
        // $request->getSession()->set('_sso_refresh_token', $tokens->refreshToken);
        // $request->getSession()->set('_sso_expires_at', time() + $tokens->expiresIn);

        // Fuer dieses Beispiel: Nur Flash-Message
        $this->addFlash('success', sprintf('Willkommen, %s!', $name ?? $email ?? $sub));
    }
}
