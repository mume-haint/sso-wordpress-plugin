<?php

class KeycloakAuth
{
  private $cookie_name = 'keycloak_sso_token';
  private $cookie_domain;

  public function __construct()
  {
    $this->cookie_domain = parse_url($_SERVER['HTTP_HOST'], PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
  }

  public function set_auth_cookie($token) {
    setcookie($this->cookie_name, $token, [
      'expires' => time() + 3600,
      'path' => '/',
      'domain' => $this->cookie_domain,
      'secure' => false,
      'httponly' => true,
      'samesite' => 'Lax'
    ]);
  }
}