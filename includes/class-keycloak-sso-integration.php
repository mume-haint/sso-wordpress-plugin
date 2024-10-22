<?php
use Jumbojett\OpenIDConnectClient;

class KeycloakSSOIntegration {
  private $oidc;
  private $auth;
  private $realm;
  private $client_id;
  private $client_secret;
  private $keycloak_url;
  private string $handle_auth_code_path = 'handle-auth-code';
  private $login_redirect_path;
  private string $authorization_code;

  public function __construct() {
    $this->realm = get_option('keycloak_realm', 'wordpress');
    $this->client_id = get_option('keycloak_client_id', '');
    $this->client_secret = get_option('keycloak_client_secret', '');
    $this->keycloak_url = get_option('keycloak_url', '');
    $this->login_redirect_path = get_option('keycloak_login_redirect_path', '');



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
    add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));

    add_action('init', array($this, 'register_handle_auth_code_endpoints'));
    add_filter('query_vars', array($this, 'add_query_vars'));
    add_action('template_redirect', array($this, 'handle_auth_code_requests'));
      add_action('rest_api_init', function () {
          register_rest_route('keycloak', '/logout', array(
              'methods' => 'POST',
              'callback' => array($this, 'handle_back_channel_logout'),
              'permission_callback' => '__return_true',
          ));
      });

    if (class_exists('KeycloakAuth')) {
      $this->auth = new KeycloakAuth($this->oidc);
    }

    if (class_exists('KeycloakShortcodes')) {
      new KeycloakShortcodes($this->realm, $this->client_id, $this->keycloak_url, $this->login_redirect_path, $this->auth);
    }
    if (class_exists('KeycloakSettings')) {
      new KeycloakSettings();
    }
  }

  public function enqueue_scripts() {
    wp_enqueue_script('jquery');
  }

  public function register_handle_auth_code_endpoints() {
    add_rewrite_rule('^handle-auth-code', 'index.php?handle-auth-code=true', 'top');
    add_rewrite_rule('^handle-logout-keycloak', 'index.php?handle-logout-keycloak=true', 'top');
      add_rewrite_rule('^handle-front-channel-logout', 'index.php?handle-front-channel-logout=true', 'top');

  }

  public function handle_auth_code_requests() {
    global $wp_query;

    if (get_query_var('handle-auth-code')) {
      $this->handle_auth_code_endpoint();
      return;
    }

    if (get_query_var('handle-logout-keycloak')) {
      $this->handle_logout_keycloak();
      return;
    }


      if (get_query_var('handle-front-channel-logout')) {
          $this->handle_front_channel_logout();
          return;
      }

    if (isset($wp_query->query_vars['name']) && $wp_query->query_vars['name'] == 'handle-auth-code') {
      $this->handle_auth_code_endpoint();
      return;
    }

    if (isset($wp_query->query_vars['name']) && $wp_query->query_vars['name'] == 'handle-logout-keycloak') {
      $this->handle_logout_keycloak();
      return;
    }

      if (isset($wp_query->query_vars['name']) && $wp_query->query_vars['name'] == 'handle-front-channel-logout') {
          $this->handle_front_channel_logout();
      }
  }

  public function add_query_vars($vars) {
    $vars[] = 'handle-auth-code';
    $vars[] = 'handle-logout-keycloak';
      $vars[] = 'handle-front-channel-logout';

      return $vars;
  }

  public function handle_auth_code_endpoint() {
    if (!isset($_GET['code'])) {
      wp_die('Authorization code not provided');
    }

    $authorization_code = sanitize_text_field($_GET['code']);
    $this->authorization_code = $authorization_code;

    try {
      $keycloak_token_url = "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/token";

      $data = [
        'grant_type' => 'authorization_code',
        'client_id' => $this->client_id,
        'client_secret' => $this->client_secret,
        'redirect_uri' => site_url($this->handle_auth_code_path),
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
        wp_die('Error occurred during token request');
      }

      $token = json_decode($response);
      $access_token = $token->access_token;
      $id_token = $token->id_token;
      if($access_token) {
        $this->auth->set_auth_cookie($access_token);
        $this->auth->set_wordpress_user($access_token);
      }
      if($id_token) {
        $this->auth->set_id_token_cookie($id_token);
      }
      ?>
      <script>
          if (window.opener) {
              console.log('This page was opened as a popup.');
              let token = '<?php echo $access_token; ?>'
              if (token) {
                  console.log('send token to main page: ', token);
                  window.opener.postMessage({
                      status: 'logged_in',
                      message: 'User successfully logged in!',
                      token: token
                  }, window.location.origin);
              } else {
                  console.error('No token found in the URL.');
              }

              window.close();
          } else {
              window.location.href = '<?php echo site_url($this->login_redirect_path) ?>'
          }
      </script>

      <?php
      exit;

    } catch (Exception $e) {
      error_log('Error handling auth code: ' . $e->getMessage());
      wp_die('Error processing authorization code');
    }
  }

  public function handle_logout_keycloak() {

    $user_id = get_current_user_id();
    if ($user_id) {

      setcookie('keycloak_access_token', '', time() - 3600, '/');
      setcookie('keycloak_id_token', '', time() - 3600, '/');

      wp_logout();

      ?>
      <script>
          if (window.opener) {
              console.log('This page was opened as a popup.');
              window.opener.postMessage({
                  status: 'logged_out',
                  message: 'User successfully logged out!',
              }, window.location.origin);

              window.close();
          } else {
              window.location.href = '<?php echo site_url($this->login_redirect_path) ?>'
          }
      </script>
<?php
    } else {
      wp_send_json_error('No user found to logout.');
    }
  }

    public function handle_front_channel_logout() {
        $host = $_SERVER['HTTP_HOST'];
        $uri = $_SERVER['REQUEST_URI'];

      error_log($host);
      error_log($uri);
    }

    function handle_back_channel_logout(WP_REST_Request $request) {
      error_log('handle_back_channel_logout' . json_decode($request));
        $logout_token = $request->get_param('logout_token');

        if (!$logout_token) {
            return new WP_REST_Response('Invalid logout token', 400);
        }

        $keycloak_jwks_url = "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/certs";
        $jwks = json_decode(file_get_contents($keycloak_jwks_url), true);

        $decoded_token = decode_jwt($logout_token, $jwks);
        if (!$decoded_token || !isset($decoded_token->sub)) {
            return new WP_REST_Response('Invalid token', 401);
        }

        $user = get_user_by('email', $decoded_token->email);
        if (!$user) {
            return new WP_REST_Response('User not found', 404);
        }

        wp_logout();

        setcookie('keycloak_access_token', '', time() - 3600, '/');
        setcookie('keycloak_id_token', '', time() - 3600, '/');

        return new WP_REST_Response('User logged out successfully', 200);
    }


}