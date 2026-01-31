# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-31

Initial beta release.

### Added

- **OidcClient**: Full OIDC client implementation
  - Auto-Discovery via `.well-known/openid-configuration`
  - Authorization Code Flow with PKCE (S256)
  - Token Exchange (`exchangeCode`)
  - Token Refresh (`refreshToken`)
  - UserInfo Endpoint (`getUserInfo`)
  - ID Token decoding (`decodeIdToken`)
  - PSR-18 HTTP Client support (framework-agnostic)

- **Symfony Bundle**: `EuripSsoBundle`
  - Bundle configuration via `eurip_sso.yaml`
  - Auto-configured `OidcClient` service via Discovery
  - `OidcClientFactory` for service creation

- **Security Integration**
  - `OidcAuthenticator` for Symfony Security
  - `OidcUserProviderInterface` for custom user mapping

- **Documentation**
  - Comprehensive README with Quick Start guide
  - `ExampleAuthController` as integration template
  - Standalone usage examples
  - Symfony Bundle integration guide

- **DTOs and Contracts**
  - `TokenResponse` for token data
  - `UserInfoResponse` for user data
  - `OidcConfig` for discovery configuration
  - `TokenExchangeFailedException` with error details
  - `OidcProtocolException` for protocol errors

### Requirements

- PHP 8.2+
- PSR-18 HTTP Client
- PSR-17 HTTP Factories
- Symfony 7.0+ / 8.x (optional, for bundle)
