<?php

class KeycloakAuth
{
  private $oidc;
  private $login_redirect_path;
  private $cookie_name = 'keycloak_sso_token';
  private $cookie_domain;

  public function __construct($oidc, $login_redirect_path)
  {
    $this->oidc = $oidc;
    $this->login_redirect_path = $login_redirect_path;
    $this->cookie_domain = parse_url($_SERVER['HTTP_HOST'], PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];

    add_action('wp_ajax_nopriv_keycloak_login', array($this, 'handle_login'));
    add_action('wp_ajax_keycloak_login', array($this, 'handle_login'));
    add_action('wp_ajax_nopriv_keycloak_signup', array($this, 'handle_signup'));
    add_action('wp_ajax_keycloak_signup', array($this, 'handle_signup'));
  }

  public function handle_login() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    try {
      $this->oidc->addAuthParam(['username' => $username]);
      $this->oidc->addAuthParam(['password' => $password]);

      $result = $this->oidc->requestResourceOwnerToken(TRUE);
      $token = $result->access_token;

      if ($token) {
        $this->set_auth_cookie($token);
        $this->set_wordpress_user($token);
        wp_send_json_success(['redirect_url' => site_url($this->login_redirect_path)]);
      } else {
        throw new Exception('Authentication failed');
      }
    } catch (Exception $e) {
      error_log('Error: ' . $e->getMessage());
      wp_send_json_error();
    }
  }

  private function set_auth_cookie($token) {
    setcookie($this->cookie_name, $token, [
      'expires' => time() + 3600,
      'path' => '/',
      'domain' => $this->cookie_domain,
      'secure' => false,
      'httponly' => true,
      'samesite' => 'Lax'
    ]);
  }

  private function set_wordpress_user($token) {
    $this->oidc->setAccessToken($token);
    try {
      $user_info = $this->oidc->requestUserInfo();
      error_log('User Info: ' . print_r($user_info, true));
      $user_email = $user_info->email;

      $user = get_user_by('email', $user_email);
      if (!$user) {
        $user_id = wp_create_user($user_info->preferred_username, wp_generate_password(), $user_email);
        $user = get_user_by('id', $user_id);
      }

      wp_set_current_user($user->ID);
      wp_set_auth_cookie($user->ID);
    } catch (Exception $e) {
      error_log('Error retrieving user info: ' . $e->getMessage());
    }
  }

  public function logout() {
    $this->oidc->signOut(NULL, site_url());
    setcookie($this->cookie_name, '', time() - 3600, '/', $this->cookie_domain, true, true);
  }
}