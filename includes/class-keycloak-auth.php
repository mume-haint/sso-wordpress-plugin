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
      $username = $user_info->preferred_username;
      $email = $user_info->email;

      // Check for an existing user by username
      $user = get_user_by('login', $username);

      if ($user) {
        // If username matches, proceed to set the user
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        return;
      }

      // If no user found by username, check for an existing user by email
      $user_by_email = get_user_by('email', $email);

      if ($user_by_email) {
        // If email is used by another account, return an error
        error_log('Error: Email conflict: ' . $email . 'with Keycloak username: ' . $username . ' and Wordpress username: ' . $user_by_email->user_login);
        // Optionally, display a message to the user
        wp_die('Email in Keycloak was already in use by another account in this site. Please change the email in the Keycloak site or this site.');
        return;
      }

      // If neither username nor email matches, create a new user
      $user_id = wp_create_user($username, wp_generate_password(), $email);
      error_log('New User ID: ' . $user_id);
      $user = get_user_by('id', $user_id);

      wp_set_current_user($user->ID);
      wp_set_auth_cookie($user->ID);
    } catch (Exception $e) {
      error_log('Error retrieving user info: ' . $e->getMessage());
    }
  }
}