# EURIP SSO Bundle

OIDC Client Library und Symfony Bundle für Single Sign-On mit EURIP SSO.

## Features

- OIDC Authorization Code Flow mit PKCE (S256)
- Auto-Discovery via `.well-known/openid-configuration`
- Discovery Document Caching
- JWT Claims Validation (iss, aud, exp, iat, nonce)
- Dual-URL Support (interne/öffentliche Issuer-URLs für Docker/Kubernetes)
- Token Exchange, Refresh und UserInfo
- PSR-3 Logging
- Symfony Bundle mit Security Authenticator
- Event System für Login-Events
- PSR-18 HTTP Client (Framework-agnostisch)

## Voraussetzungen

- PHP 8.2+
- Symfony 7.0+ oder 8.0+
- PSR-18 HTTP Client (z.B. `symfony/http-client` + `nyholm/psr7`)

## Installation

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

### Bundle registrieren

```php
// config/bundles.php
return [
    // ...
    Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
];
```

### PSR-18 HTTP Client einrichten

Das Bundle benötigt einen PSR-18 kompatiblen HTTP Client:

```bash
composer require symfony/http-client nyholm/psr7
```

```yaml
# config/packages/psr18.yaml
services:
    Psr\Http\Client\ClientInterface:
        class: Symfony\Component\HttpClient\Psr18Client

    Psr\Http\Message\RequestFactoryInterface:
        class: Nyholm\Psr7\Factory\Psr17Factory

    Psr\Http\Message\StreamFactoryInterface:
        class: Nyholm\Psr7\Factory\Psr17Factory
```

---

## Konfiguration

### Vollständige Konfigurationsreferenz

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    # ============================================================
    # OIDC Provider Einstellungen (erforderlich)
    # ============================================================

    # OIDC Issuer URL - für Server-zu-Server Kommunikation
    # In Docker-Umgebungen oft die interne Container-URL
    issuer: '%env(SSO_ISSUER_URL)%'

    # OIDC Client ID
    client_id: '%env(OIDC_CLIENT_ID)%'

    # Redirect URI für Authorization Callback
    redirect_uri: '%env(APP_URL)%/auth/callback'

    # ============================================================
    # OIDC Provider Einstellungen (optional)
    # ============================================================

    # Client Secret (optional für Public Clients)
    # Standard: null
    client_secret: null

    # Öffentliche Issuer URL für Browser-Redirects
    # Verwenden wenn issuer eine interne URL ist (z.B. Docker)
    # Standard: null (verwendet issuer)
    public_issuer: '%env(SSO_PUBLIC_URL)%'

    # OIDC Scopes
    # Standard: [openid, profile, email]
    scopes:
        - openid
        - profile
        - email

    # ============================================================
    # Discovery Caching
    # ============================================================
    cache:
        # Caching aktivieren
        # Standard: true
        enabled: true

        # Cache TTL in Sekunden
        # Standard: 3600 (1 Stunde)
        ttl: 3600

        # Symfony Cache Pool Service ID
        # Standard: cache.app
        pool: cache.app

    # ============================================================
    # Security Authenticator Einstellungen
    # ============================================================
    authenticator:
        # Pfad für den SSO Callback
        # Standard: /auth/callback
        callback_route: '/auth/callback'

        # Standard-Redirect nach erfolgreichem Login
        # Standard: /
        default_target_path: '/'

        # Redirect-Pfad bei Authentifizierungsfehler
        # Standard: /login
        login_path: '/login'

        # ID Token Signatur via JWKS verifizieren
        # Standard: false
        verify_signature: false
```

### Minimale Konfiguration

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER_URL)%'
    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: '%env(APP_URL)%/auth/callback'
```

### Docker/Kubernetes Konfiguration (Dual-URL)

Wenn der SSO-Server intern über eine andere URL erreichbar ist als vom Browser:

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    # Interne URL für Token-Exchange (Server-zu-Server)
    issuer: 'http://sso-container:8080'

    # Öffentliche URL für Browser-Redirects
    public_issuer: 'https://sso.example.com'

    client_id: '%env(OIDC_CLIENT_ID)%'
    redirect_uri: 'https://app.example.com/auth/callback'
```

### Environment Variables

```env
# .env
SSO_ISSUER_URL=https://sso.eurip.com
SSO_PUBLIC_URL=https://sso.eurip.com
OIDC_CLIENT_ID=my-app
OIDC_CLIENT_SECRET=your-secret
APP_URL=https://my-app.com
```

---

## Standalone Usage (ohne Symfony Bundle)

### Client erstellen via Discovery

```php
use Jostkleigrewe\Sso\Client\OidcClient;

$client = OidcClient::fromDiscovery(
    issuer: 'https://sso.example.com',
    clientId: 'my-app',
    redirectUri: 'https://my-app.com/callback',
    httpClient: $psrHttpClient,
    requestFactory: $psrRequestFactory,
    streamFactory: $psrStreamFactory,
    clientSecret: 'optional-secret', // null für Public Clients
);
```

### Authorization URL erstellen

```php
$authData = $client->buildAuthorizationUrl(['openid', 'profile', 'email']);

// In Session speichern für Callback-Validierung
$_SESSION['oauth_state'] = $authData['state'];
$_SESSION['oauth_nonce'] = $authData['nonce'];
$_SESSION['oauth_verifier'] = $authData['code_verifier'];

// User zum IdP redirecten
header('Location: ' . $authData['url']);
```

### Authorization Code austauschen

```php
// Im Callback (/callback?code=xxx&state=xxx)
$code = $_GET['code'];
$state = $_GET['state'];

// State validieren
if ($state !== $_SESSION['oauth_state']) {
    throw new Exception('Invalid state');
}

// Code gegen Tokens tauschen
$tokens = $client->exchangeCode($code, $_SESSION['oauth_verifier']);

echo $tokens->accessToken;
echo $tokens->idToken;
echo $tokens->refreshToken;
echo $tokens->expiresIn;
```

### Claims validieren

```php
$claims = $client->decodeIdToken($tokens->idToken);

// Claims validieren (wirft ClaimsValidationException bei Fehlern)
$client->validateClaims(
    claims: $claims,
    expectedNonce: $_SESSION['oauth_nonce'],
);
```

### UserInfo abrufen

```php
$userInfo = $client->getUserInfo($tokens->accessToken);

echo $userInfo->sub;   // User ID
echo $userInfo->email; // E-Mail (optional)
echo $userInfo->name;  // Name (optional)
```

### Token erneuern

```php
$newTokens = $client->refreshToken($tokens->refreshToken);
```

### Logout URL erstellen

```php
$logoutUrl = $client->buildLogoutUrl(
    idTokenHint: $tokens->idToken,
    postLogoutRedirectUri: 'https://my-app.com/',
);
header('Location: ' . $logoutUrl);
```

---

## Symfony Bundle Usage

### OidcClient als Service nutzen

```php
use Jostkleigrewe\Sso\Client\OidcClient;

class AuthController extends AbstractController
{
    public function __construct(
        private readonly OidcClient $oidcClient,
    ) {}

    #[Route('/login', name: 'app_login')]
    public function login(SessionInterface $session): Response
    {
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        $session->set('oauth_state', $state);
        $session->set('oauth_nonce', $nonce);

        $authUrl = $this->oidcClient->buildAuthorizationUrl(
            scopes: ['openid', 'profile', 'email'],
            state: $state,
            nonce: $nonce,
        );

        return $this->redirect($authUrl);
    }

    #[Route('/auth/callback', name: 'app_callback')]
    public function callback(Request $request, SessionInterface $session): Response
    {
        $code = $request->query->get('code');
        $state = $request->query->get('state');

        if ($state !== $session->get('oauth_state')) {
            throw new \RuntimeException('Invalid state');
        }

        $tokenResponse = $this->oidcClient->exchangeCode($code);
        $claims = $this->oidcClient->decodeIdToken($tokenResponse->idToken);

        $this->oidcClient->validateClaims(
            claims: $claims,
            expectedNonce: $session->get('oauth_nonce'),
        );

        $userInfo = $this->oidcClient->getUserInfo($tokenResponse->accessToken);

        $session->remove('oauth_state');
        $session->remove('oauth_nonce');

        // User anlegen/aktualisieren und einloggen...

        return $this->redirectToRoute('app_home');
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(SessionInterface $session): Response
    {
        $idToken = $session->get('id_token');
        $session->invalidate();

        $logoutUrl = $this->oidcClient->buildLogoutUrl(
            idTokenHint: $idToken,
            postLogoutRedirectUri: 'https://app.example.com/',
        );

        return $this->redirect($logoutUrl);
    }
}
```

### Security Authenticator verwenden

#### 1. User Provider implementieren

```php
use Jostkleigrewe\Sso\Bundle\Security\OidcUserProviderInterface;
use Jostkleigrewe\Sso\Contracts\DTO\UserInfoResponse;
use Symfony\Component\Security\Core\User\UserInterface;

class OidcUserProvider implements OidcUserProviderInterface
{
    public function __construct(
        private readonly UserRepository $userRepository,
    ) {}

    public function loadOrCreateUser(array $claims, UserInfoResponse $userInfo): UserInterface
    {
        $user = $this->userRepository->findOneBy([
            'oidcIssuer' => $claims['iss'],
            'oidcSubject' => $claims['sub'],
        ]);

        if (!$user) {
            $user = new User();
            $user->setOidcIssuer($claims['iss']);
            $user->setOidcSubject($claims['sub']);
        }

        $user->setEmail($userInfo->email);
        $user->setName($userInfo->name);

        $this->userRepository->save($user, flush: true);

        return $user;
    }
}
```

#### 2. User Provider registrieren

```yaml
# config/services.yaml
services:
    App\Security\OidcUserProvider:
        autowire: true

    Jostkleigrewe\Sso\Bundle\Security\OidcUserProviderInterface:
        alias: App\Security\OidcUserProvider
```

#### 3. Security Firewall konfigurieren

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            custom_authenticators:
                - Jostkleigrewe\Sso\Bundle\Security\OidcAuthenticator
```

---

## Events

Das Bundle dispatcht Events für Login-Vorgänge:

### OidcLoginSuccessEvent

Wird nach erfolgreichem Login dispatcht.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginSuccessEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
class LoginSuccessListener
{
    public function __invoke(OidcLoginSuccessEvent $event): void
    {
        $user = $event->user;
        $claims = $event->claims;
        $tokenResponse = $event->tokenResponse;

        // Audit Log, Statistik, etc.
    }
}
```

### OidcLoginFailureEvent

Wird bei fehlgeschlagenem Login dispatcht.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcLoginFailureEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
class LoginFailureListener
{
    public function __invoke(OidcLoginFailureEvent $event): void
    {
        $error = $event->error;
        $errorDescription = $event->errorDescription;
        $exception = $event->exception;

        // Logging, Alerting, etc.
    }
}
```

### OidcTokenRefreshedEvent

Wird nach Token-Refresh dispatcht.

```php
use Jostkleigrewe\Sso\Bundle\Event\OidcTokenRefreshedEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
class TokenRefreshedListener
{
    public function __invoke(OidcTokenRefreshedEvent $event): void
    {
        $newTokenResponse = $event->tokenResponse;
        $previousAccessToken = $event->previousAccessToken;
    }
}
```

---

## DTOs

### TokenResponse

```php
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;

$tokenResponse = $oidcClient->exchangeCode($code);

$tokenResponse->accessToken;   // string
$tokenResponse->idToken;       // string|null
$tokenResponse->refreshToken;  // string|null
$tokenResponse->expiresIn;     // int (Sekunden)
$tokenResponse->tokenType;     // string (meist "Bearer")
```

### UserInfoResponse

```php
use Jostkleigrewe\Sso\Contracts\DTO\UserInfoResponse;

$userInfo = $oidcClient->getUserInfo($accessToken);

$userInfo->sub;            // string - Subject (User ID)
$userInfo->email;          // string|null
$userInfo->emailVerified;  // bool|null
$userInfo->name;           // string|null
```

---

## Exception Handling

```php
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Jostkleigrewe\Sso\Contracts\Exception\ClaimsValidationException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcException;

try {
    $tokenResponse = $oidcClient->exchangeCode($code);
    $claims = $oidcClient->decodeIdToken($tokenResponse->idToken);
    $oidcClient->validateClaims($claims, $nonce);
} catch (TokenExchangeFailedException $e) {
    // Token Exchange fehlgeschlagen
    $error = $e->error;              // z.B. "invalid_grant"
    $errorDescription = $e->errorDescription;
} catch (ClaimsValidationException $e) {
    // Claims Validation fehlgeschlagen
    // z.B. Token abgelaufen, falscher Issuer, etc.
} catch (OidcException $e) {
    // Allgemeiner OIDC Fehler
}
```

### ClaimsValidationException Typen

```php
ClaimsValidationException::invalidIssuer($expected, $actual);
ClaimsValidationException::invalidAudience($expected, $actual);
ClaimsValidationException::tokenExpired($exp, $now);
ClaimsValidationException::tokenNotYetValid($iat, $now);
ClaimsValidationException::invalidNonce($expected, $actual);
ClaimsValidationException::missingClaim($claimName);
```

---

## PKCE Support

PKCE (Proof Key for Code Exchange) ist standardmäßig aktiviert mit der S256-Methode.
Der `code_verifier` wird automatisch generiert und muss zwischen Authorization Request
und Token Exchange in der Session gespeichert werden.

---

## Development

```bash
# Dependencies installieren
composer install

# Tests ausführen
composer test

# Coding Standards prüfen
composer cs

# Coding Standards automatisch fixen
composer cs:fix

# PHPStan Analyse
composer stan

# Alle Quality Checks
composer quality
```

---

## Unterstützte Grant Types

| Grant Type | Methode |
|------------|---------|
| Authorization Code | `exchangeCode()` |
| Refresh Token | `refreshToken()` |

---

## Lizenz

MIT License
