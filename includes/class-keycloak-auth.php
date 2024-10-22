<?php

class KeycloakAuth
{
  private $oidc;
  private $cookie_name = 'keycloak_sso_token';
  private $cookie_id_token = 'keycloak_id_token';
  private $cookie_domain;

  public function __construct($oidc)
  {
    $this->oidc = $oidc;
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

  public function set_id_token_cookie($id_token) {
    setcookie($this->cookie_id_token, $id_token, [
      'expires' => time() + 3600,
      'path' => '/',
      'domain' => $this->cookie_domain,
      'secure' => false,
      'httponly' => true,
      'samesite' => 'Lax'
    ]);
  }

  public function set_wordpress_user($token) {
    $this->oidc->setAccessToken($token);
    try {
      $user_info = $this->oidc->requestUserInfo();
      error_log('User Info: ' . print_r($user_info, true));
      $user_email = $user_info->email;

      $user = get_user_by('email', $user_email);
      if (!$user) {
        $user_id = wp_create_user($user_info->preferred_username, wp_generate_password(), $user_email);
        error_log('User ID: ' . $user_id);
        $user = get_user_by('id', $user_id);
      }

      wp_set_current_user($user->ID);
      wp_set_auth_cookie($user->ID);
    } catch (Exception $e) {
      error_log('Error retrieving user info: ' . $e->getMessage());
    }
  }
}