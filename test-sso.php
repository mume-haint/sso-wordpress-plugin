<?php
/*
Plugin Name: Test SSO
Description: Integrates Keycloak SSO into WordPress using OpenID Connect (Multi-site Support) with Signup Feature
Version: 1.2
Author: Khoi Tran (Updated by Assistant)
*/

require __DIR__ . '/vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;

class KeycloakSSOIntegration {
  private $oidc;
  private $cookie_name = 'keycloak_sso_token';
  private $cookie_domain;
  private $realm;
  private $client_id;
  private $client_secret;
  private $keycloak_url;
  private $login_path;
  private $login_redirect_path;

  private $authorization_code;

  public function enqueue_scripts() {
    wp_enqueue_script('jquery');

    // Get the current path without query parameters
    $current_path = parse_url(home_url($_SERVER['REQUEST_URI']), PHP_URL_PATH);
    // Get the login redirect path
    $login_redirect_path = untrailingslashit($this->login_redirect_path);

    // Compare only the path
    if (untrailingslashit($current_path) === $login_redirect_path) {
      wp_enqueue_script('keycloak-popup-handler', plugin_dir_url(__FILE__) . 'js/popup-handler.js', array('jquery'), '1.0', true);
    }
  }



  public function __construct() {
    $this->cookie_domain = parse_url($_SERVER['HTTP_HOST'], PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    $this->realm = get_option('keycloak_realm', 'wordpress');
    $this->client_id = get_option('keycloak_client_id', 'demo-client');
    $this->client_secret = get_option('keycloak_client_secret', 'PNFIKU0jUX4DCC27TsZgVS8E8r8dIk53');
    $this->keycloak_url = get_option('keycloak_url', 'http://host.docker.internal:8888');
    $this->login_path = get_option('keycloak_login_page_path', '/login');
    $this->login_redirect_path = get_option('keycloak_login_redirect_path', '/');

    $this->oidc = new OpenIDConnectClient(
      "{$this->keycloak_url}/realms/{$this->realm}",
      $this->client_id,
      $this->client_secret
    );

    $this->oidc->providerConfigParam([
      'token_endpoint' => "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/token",
      'userinfo_endpoint' => "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/userinfo",
      'jwks_uri' => "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/certs",
      'authorization_endpoint' => "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/auth"
    ]);

    $this->oidc->addScope(['openid', 'profile', 'email']);

    // Add hooks
    add_action('wp', array($this, 'init_auth'));
//    add_action('wp_logout', array($this, 'logout'));
    add_shortcode('keycloak_login_form', array($this, 'login_form_shortcode'));
    add_shortcode('keycloak_signup_form', array($this, 'signup_form_shortcode'));
    add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));

    add_action('admin_menu', array($this, 'add_admin_menu'));
    add_action('admin_init', array($this, 'register_settings'));
  }

  public function init_auth() {
    if (is_admin() || wp_doing_ajax()) {
      return;
    }
    error_log('Is main page ' . is_page() && site_url($this->login_redirect_path) === home_url(add_query_arg(null, null)));

    error_log('Login path '. $this->login_path);

    $page_login = get_page_by_path( $this->login_path );

    if (!$page_login) {
      error_log('Login page not found.');
      return;
    }

    $login_page_id = $page_login->ID;

    error_log('Isset cookie: ' . isset($_COOKIE[$this->cookie_name]));
    error_log('Is login page: ' . is_page($login_page_id));

//    if (isset($_COOKIE[$this->cookie_name])) {
//      $token = $_COOKIE[$this->cookie_name];
//
//      if ($this->is_token_valid($token)) {
//        $this->set_wordpress_user($token);
//
//        if (is_page($login_page_id)) {
//          error_log('Redirecting from login page to homepage');
//          wp_redirect(site_url($this->login_redirect_path));
//          exit;
//        }
//      } else {
//        error_log('Invalid token. Clearing cookie and redirecting to login page');
//        setcookie($this->cookie_name, '', time() - 3600, '/', $this->cookie_domain, true, true);
//        if (!is_page($login_page_id)) {
//          wp_redirect(get_page_link($login_page_id));
//          exit;
//        }
//      }
//    } else {
//      if (!is_page($login_page_id)) {
//        wp_redirect(get_page_link($login_page_id));
//      }
//    }
  }


  public function login_form_shortcode()
  {
    ob_start();
    ?>
    <button id="keycloak-login-btn">Login with Keycloak</button>

    <script>
        jQuery(document).ready(function ($) {
            $('#keycloak-login-btn').on('click', function (e) {
                e.preventDefault();

                var keycloakAuthUrl = '<?php echo $this->get_keycloak_auth_url(); ?>';
                var popup = window.open(keycloakAuthUrl, 'keycloakLogin', 'width=600,height=700');

                if (!popup || popup.closed || typeof popup.closed == 'undefined') {
                    alert('Popup blocked! Please allow popups for this website.');
                    return;
                }
                window.addEventListener('message', function (event) {
                    if (event.origin !== window.location.origin) {
                        return;
                    }

                    if (event.data.status === 'logged_in') {
                        console.log(event.data.code)
                        $.ajax({
                            url: '<?php echo admin_url('admin-ajax.php'); ?>',
                            type: 'POST',
                            data: {
                                action: 'keycloak_handle_auth_code',
                                code: event.data.code
                            },
                            success: function (response) {
                                if (response.success) {
                                    console.log('Authorization code processed successfully.');
                                    window.location.href = response.redirect_url;
                                } else {
                                    console.error('Failed to process authorization code: ', response);
                                }
                            },
                            error: function (jqXHR, textStatus, errorThrown) {
                                console.error('Error processing authorization code: ', textStatus, errorThrown);
                            }
                        });
                    }
                }, false);
            });
        });
    </script>
    <?php
    return ob_get_clean();
  }





  public function signup_form_shortcode() {
    ob_start();
    ?>
    <form id="keycloak-signup-form">
      <input type="text" name="username" placeholder="Username" required>
      <input type="email" name="email" placeholder="Email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Signup</button>
    </form>
    <script>
        jQuery(document).ready(function($) {
            $('#keycloak-signup-form').on('submit', function(e) {
                e.preventDefault();
                var username = $('input[name="username"]').val();
                var email = $('input[name="email"]').val();
                var password = $('input[name="password"]').val();

                $.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'keycloak_signup',
                        username: username,
                        email: email,
                        password: password
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('Signup success. You can now login.');
                        } else {
                            alert('Signup failed. Please try again.');
                            console.log(response);
                        }
                    }
                });
            });
        });
    </script>
    <?php
    return ob_get_clean();
  }

  public function handle_signup() {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    $signup_url = "{$this->keycloak_url}/admin/realms/{$this->realm}/users";

    $data = array(
      'username' => $username,
      'email' => $email,
      'enabled' => true,
      'credentials' => array(
        array(
          'type' => 'password',
          'value' => $password,
          'temporary' => false
        )
      )
    );

    $headers = array(
      'content-type' => 'application/json',
      'authorization' => 'Bearer ' . $this->get_admin_token(),
    );

    $response = wp_remote_post($signup_url, array(
      'body' => json_encode($data),
      'headers' => $headers
    ));

    if (is_wp_error($response)) {
      error_log('Error in wp_remote_post: ' . $response->get_error_message());
      wp_send_json_error();
    } else {
      wp_send_json_success();
    }
  }

  private function get_admin_token() {

    // Add auth parameters as URL-encoded form data
    $auth_data = [
      'username' => 'admin',
      'password' => '123456',
      'grant_type' => 'password',
      'client_id' => 'admin-cli'
    ];

    // Define headers
    $headers = [
      'Content-Type' => 'application/x-www-form-urlencoded'
    ];

    // Convert data to URL-encoded format
    $body = http_build_query($auth_data);

    // Make the request to the token endpoint
    $response = wp_remote_post("{$this->keycloak_url}/realms/master/protocol/openid-connect/token", [
      'body' => $body,
      'headers' => $headers
    ]);

    if (is_wp_error($response)) {
      error_log('Error fetching admin token: ' . $response->get_error_message());
      return null;
    }

    $response_body = wp_remote_retrieve_body($response);
    $token_response = json_decode($response_body);
    error_log('Response Body from get_admin_token: ' . $response_body);
    if (isset($token_response->access_token)) {
      return $token_response->access_token;
    } else {
      error_log('Failed to retrieve access token: ' . print_r($token_response, true));
      return null;
    }
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

  private function is_token_valid($token) {
    try {
      $this->oidc->setAccessToken($token);
      $user_info = $this->oidc->requestUserInfo();

      return !empty($user_info);
    } catch (Exception $e) {
      error_log('Token validation error: ' . $e->getMessage());
      return false;
    }
  }

  private function get_keycloak_auth_url() {
    $redirect_uri = site_url($this->login_redirect_path); // The URL Keycloak should redirect to after successful login
    $state = bin2hex(random_bytes(16)); // Optional, to maintain state between requests

    // Construct the authorization URL
    $auth_url = "http://localhost:8888/realms/{$this->realm}/protocol/openid-connect/auth";
    $auth_url .= '?response_type=code';
    $auth_url .= '&client_id=' . urlencode($this->client_id);
    $auth_url .= '&redirect_uri=' . urlencode($redirect_uri);
    $auth_url .= '&scope=' . urlencode('openid profile email');
    $auth_url .= '&state=' . urlencode($state);

    return $auth_url;
  }



  public function add_admin_menu() {
    add_options_page(
      'Keycloak SSO Settings',
      'Keycloak SSO',
      'manage_options',
      'keycloak-sso-settings',
      array($this, 'settings_page')
    );
  }

  public function register_settings() {
    // Register settings
    register_setting('keycloak_sso_settings_group', 'keycloak_client_id');
    register_setting('keycloak_sso_settings_group', 'keycloak_client_secret');
    register_setting('keycloak_sso_settings_group', 'keycloak_url');
    register_setting('keycloak_sso_settings_group', 'keycloak_realm');
    register_setting('keycloak_sso_settings_group', 'keycloak_login_page_path');
    register_setting('keycloak_sso_settings_group', 'keycloak_login_redirect_path');
  }


  public function settings_page() {
    ?>
    <div class="wrap">
      <h1>Keycloak SSO Settings</h1>
      <form method="post" action="options.php">
        <?php
        settings_fields('keycloak_sso_settings_group');
        do_settings_sections('keycloak_sso_settings_group');
        ?>
        <table class="form-table">
          <tr valign="top">
            <th scope="row">Client ID</th>
            <td><input type="text" name="keycloak_client_id" value="<?php echo esc_attr(get_option('keycloak_client_id')); ?>" /></td>
          </tr>
          <tr valign="top">
            <th scope="row">Client Secret</th>
            <td><input type="text" name="keycloak_client_secret" value="<?php echo esc_attr(get_option('keycloak_client_secret')); ?>" /></td>
          </tr>
          <tr valign="top">
            <th scope="row">Keycloak URL</th>
            <td><input type="text" name="keycloak_url" value="<?php echo esc_attr(get_option('keycloak_url')); ?>" /></td>
          </tr>
          <tr valign="top">
            <th scope="row">Realm</th>
            <td><input type="text" name="keycloak_realm" value="<?php echo esc_attr(get_option('keycloak_realm')); ?>" /></td>
          </tr>
          <tr valign="top">
            <th scope="row">Login Page Path</th>
            <td><input type="text" name="keycloak_login_page_path" value="<?php echo esc_attr(get_option('keycloak_login_page_path')); ?>" placeholder="/login" /></td>
          </tr>
          <tr valign="top">
            <th scope="row">Login Redirect Path</th>
            <td><input type="text" name="keycloak_login_redirect_path" value="<?php echo esc_attr(get_option('keycloak_login_redirect_path')); ?>" placeholder="/" /></td>
          </tr>
        </table>
        <?php submit_button(); ?>
      </form>
    </div>
    <?php
  }

  public function handle_auth_code() {
    if (!isset($_POST['code'])) {
      wp_send_json_error('Authorization code not provided');
      return;
    }

    $authorization_code = sanitize_text_field($_POST['code']);
    $this->authorization_code = $authorization_code;
    error_log($this->authorization_code);
    try {
      $keycloak_token_url = "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/token";

      $data = [
        'grant_type' => 'authorization_code',
        'client_id' => $this->client_id,
        'client_secret' => $this->client_secret,
        'redirect_uri' => $this->login_redirect_path,
        'code' => $this->authorization_code,
      ];

      $options = [
        'http' => [
          'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
          'method'  => 'POST',
          'content' => http_build_query($data),
        ],
      ];

      $context  = stream_context_create($options);
      $response = file_get_contents($keycloak_token_url, false, $context);

      if ($response === FALSE) {
        $error = error_get_last();

        die('Error occurred during token request: ' .
          $error['message'] .
          ' in ' .
          $error['file'] .
          ' on line ' .
          $error['line']);
      }

      $token = json_decode($response);

      $access_token = $token->access_token;
      $this->set_wordpress_user($access_token);
    } catch (Exception $e) {
      error_log('Error handling auth code: ' . $e->getMessage());
      wp_send_json_error('Error processing authorization code');
    }
  }

}
register_uninstall_hook(__FILE__, 'keycloak_sso_uninstall');

function keycloak_sso_uninstall() {
  delete_option('keycloak_client_id');
  delete_option('keycloak_client_secret');
  delete_option('keycloak_url');
  delete_option('keycloak_realm');
  delete_option('keycloak_login_page_path');
  delete_option('keycloak_login_redirect_path');
}

$keycloak_sso = new KeycloakSSOIntegration();

add_action('wp_ajax_nopriv_keycloak_login', array($keycloak_sso, 'handle_login'));
add_action('wp_ajax_keycloak_login', array($keycloak_sso, 'handle_login'));
add_action('wp_ajax_nopriv_keycloak_signup', array($keycloak_sso, 'handle_signup'));
add_action('wp_ajax_keycloak_signup', array($keycloak_sso, 'handle_signup'));
add_action('wp_ajax_nopriv_keycloak_handle_auth_code', array($keycloak_sso, 'handle_auth_code'));
add_action('wp_ajax_keycloak_handle_auth_code', array($keycloak_sso, 'handle_auth_code'));

