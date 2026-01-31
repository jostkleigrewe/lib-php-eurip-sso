# EURIP SSO Client Library

OIDC Client Library und Symfony Bundle für die Integration mit EURIP SSO.

## Features

- OIDC Authorization Code Flow mit PKCE (S256)
- Auto-Discovery via `.well-known/openid-configuration`
- Token Exchange, Refresh und UserInfo
- Symfony Bundle mit Security Authenticator
- PSR-18 HTTP Client (Framework-agnostisch)

## Installation

```bash
composer require jostkleigrewe/lib-php-eurip-sso
```

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

### ID Token dekodieren

```php
$claims = $client->decodeIdToken($tokens->idToken);

echo $claims['sub'];   // Subject
echo $claims['email']; // E-Mail
echo $claims['iss'];   // Issuer
echo $claims['aud'];   // Audience (Client ID)
```

## Symfony Bundle - Quick Start

### Schritt 1: Bundle installieren

```bash
# Via Packagist (wenn veroeffentlicht)
composer require jostkleigrewe/lib-php-eurip-sso

# Oder als Path-Repository (lokal)
# In composer.json:
{
    "repositories": [
        {"type": "path", "url": "../bundles/lib-php-eurip-sso"}
    ],
    "require": {
        "jostkleigrewe/lib-php-eurip-sso": "*"
    }
}
```

### Schritt 2: Bundle registrieren

```php
// config/bundles.php
return [
    // ...
    Jostkleigrewe\Sso\Bundle\EuripSsoBundle::class => ['all' => true],
];
```

### Schritt 3: Konfiguration

```yaml
# config/packages/eurip_sso.yaml
eurip_sso:
    issuer: '%env(SSO_ISSUER)%'
    client_id: '%env(SSO_CLIENT_ID)%'
    client_secret: '%env(SSO_CLIENT_SECRET)%'  # optional
    redirect_uri: '%env(SSO_REDIRECT_URI)%'
    scopes:
        - openid
        - profile
        - email
```

```env
# .env
SSO_ISSUER=https://sso.eurip.com
SSO_CLIENT_ID=my-app
SSO_CLIENT_SECRET=your-secret
SSO_REDIRECT_URI=https://my-app.com/auth/callback
```

### Schritt 4: HTTP Client bereitstellen

Das Bundle benoetigt einen PSR-18 HTTP Client. Mit Symfony HttpClient:

```bash
composer require symfony/http-client nyholm/psr7
```

```yaml
# config/services.yaml
services:
    Psr\Http\Client\ClientInterface:
        class: Symfony\Component\HttpClient\Psr18Client

    Psr\Http\Message\RequestFactoryInterface:
        class: Nyholm\Psr7\Factory\Psr17Factory

    Psr\Http\Message\StreamFactoryInterface:
        class: Nyholm\Psr7\Factory\Psr17Factory
```

### Schritt 5: Auth Controller erstellen

Kopiere den ExampleController und passe ihn an:

```bash
cp vendor/jostkleigrewe/lib-php-eurip-sso/src/Bundle/Controller/ExampleAuthController.php \
   src/Controller/AuthController.php
```

Dann im Controller:
1. Namespace aendern zu `App\Controller`
2. Klassennamen aendern zu `AuthController`
3. Routes hinzufuegen (Attributes oder routes.yaml)
4. `handleSuccessfulLogin()` anpassen

```php
// src/Controller/AuthController.php
namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

class AuthController extends AbstractController
{
    // ...

    #[Route('/auth/login', name: 'app_auth_login')]
    public function login(Request $request): RedirectResponse
    {
        // ... (aus ExampleController)
    }

    #[Route('/auth/callback', name: 'app_auth_callback')]
    public function callback(Request $request): Response
    {
        // ... (aus ExampleController)
    }
}
```

### Schritt 6 (Optional): Security Authenticator

Alternativ zum manuellen Controller kannst du den OidcAuthenticator nutzen:

#```php
namespace App\Security;

use Jostkleigrewe\Sso\Bundle\Security\OidcUserProviderInterface;
use Jostkleigrewe\Sso\Contracts\DTO\TokenResponse;
use Symfony\Component\Security\Core\User\UserInterface;

class OidcUserProvider implements OidcUserProviderInterface
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly OidcClient $oidcClient,
    ) {}

    public function loadOrCreateUser(string $sub, TokenResponse $tokenResponse): UserInterface
    {
        // Bestehenden User laden
        $user = $this->userRepository->findByOidcSub($sub);

        if ($user !== null) {
            return $user;
        }

        // Neuen User erstellen
        $claims = $this->oidcClient->decodeIdToken($tokenResponse->idToken);

        $user = new User();
        $user->setOidcSub($sub);
        $user->setEmail($claims['email'] ?? null);
        $user->setName($claims['name'] ?? null);

        $this->userRepository->save($user);

        return $user;
    }
}
```

#### Security Firewall konfigurieren

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            custom_authenticators:
                - Jostkleigrewe\Sso\Bundle\Security\OidcAuthenticator
```

---

## OidcClient als Service nutzen

```php
use Jostkleigrewe\Sso\Client\OidcClient;

class MyController
{
    public function __construct(
        private readonly OidcClient $oidcClient,
    ) {}

    public function someAction(): Response
    {
        // Client ist bereits konfiguriert
        $authData = $this->oidcClient->buildAuthorizationUrl();
        // ...
    }
}
```

## Error Handling

```php
use Jostkleigrewe\Sso\Contracts\Exception\TokenExchangeFailedException;
use Jostkleigrewe\Sso\Contracts\Exception\OidcProtocolException;

try {
    $tokens = $client->exchangeCode($code, $verifier);
} catch (TokenExchangeFailedException $e) {
    // Token Exchange fehlgeschlagen
    echo $e->error;            // z.B. "invalid_grant"
    echo $e->errorDescription; // z.B. "Code expired"
} catch (OidcProtocolException $e) {
    // Protokollfehler (z.B. ungültige Response)
    echo $e->getMessage();
}
```

## Unterstützte Grant Types

| Grant Type | Methode |
|------------|---------|
| Authorization Code | `exchangeCode()` |
| Refresh Token | `refreshToken()` |

## PKCE Support

PKCE (Proof Key for Code Exchange) ist standardmäßig aktiviert mit der S256-Methode.
Der `code_verifier` wird automatisch generiert und muss zwischen Authorization Request
und Token Exchange in der Session gespeichert werden.

## Anforderungen

- PHP 8.2+
- PSR-18 HTTP Client (z.B. Guzzle, Symfony HttpClient)
- PSR-17 HTTP Factories (z.B. nyholm/psr7)

## Lizenz

MIT License - siehe [LICENSE](LICENSE)
