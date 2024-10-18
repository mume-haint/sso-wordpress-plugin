<?php
use Jumbojett\OpenIDConnectClient;

class KeycloakSSOIntegration {
  private $oidc;
  private $realm;
  private $client_id;
  private $client_secret;
  private $keycloak_url;
  private $login_path;
  private string $handle_auth_code_path = 'handle-auth-code';
  private $login_redirect_path;
  private string $authorization_code;

  public function __construct() {
    $this->realm = get_option('keycloak_realm', 'wordpress');
    $this->client_id = get_option('keycloak_client_id', 'demo-client');
    $this->client_secret = get_option('keycloak_client_secret', 'PNFIKU0jUX4DCC27TsZgVS8E8r8dIk53');
    $this->keycloak_url = get_option('keycloak_url', 'http://host.docker.internal:8888');
    $this->login_path = get_option('keycloak_login_page_path', '/login');
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
    add_action('wp', array($this, 'init_auth'));
    add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));

    add_action('init', array($this, 'register_handle_auth_code_endpoints'));
    add_filter('query_vars', array($this, 'add_query_vars'));
    add_action('template_redirect', array($this, 'handle_auth_code_requests'));

    if (class_exists('KeycloakAuth')) {
      new KeycloakAuth($this->oidc, $this->login_redirect_path);
    }

    error_log("Class short code exists: " . class_exists('KeycloakShortcodes'));
    if (class_exists('KeycloakShortcodes')) {
      new KeycloakShortcodes($this->realm, $this->client_id, $this->keycloak_url, $this->login_redirect_path);
    }
    if (class_exists('KeycloakSettings')) {
      new KeycloakSettings();
    }
  }

  public function enqueue_scripts() {
    wp_enqueue_script('jquery');
  }

  public function init_auth() {
    if (is_admin() || wp_doing_ajax()) {
      return;
    }

    $page_login = get_page_by_path( $this->login_path );

    if (!$page_login) {
      error_log('Login page not found.');
    }
  }

  public function register_handle_auth_code_endpoints() {
    add_rewrite_rule('^handle-auth-code/?', 'index.php?handle-auth-code=1', 'top');
  }

  public function handle_auth_code_requests() {
    if (get_query_var('handle-auth-code') == 'true') {
      handle_auth_code_endpoint();
      exit;
    }
    error_log('handle_auth_code_requests');
    global $wp_query;
    error_log(json_encode($wp_query->query_vars));
    if (isset($wp_query->query_vars['name']) && $wp_query->query_vars['name'] == 'handle-auth-code') {
      $this->handle_auth_code_endpoint();
    }
  }

  public function add_query_vars($vars) {
    error_log('add_query_vars');
    $vars[] = 'handle-auth-code';
    return $vars;
  }

  public function handle_auth_code_endpoint() {
    error_log('handle_auth_code_endpoint');
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
      error_log('Access token: '. $access_token);
      ?>
      <script>
          if (window.opener) {
              console.log('This page was opened as a popup.');
              let token = '<?php echo $access_token; ?>'
              if (token) {
                  window.opener.postMessage({
                      status: 'logged_in',
                      message: 'User successfully logged in!',
                      token: token
                  }, window.location.origin);
              } else {
                  console.error('No token found in the URL.');
              }

              window.close();
          }
      </script>

      <?php
//      $this->set_wordpress_user($access_token);

      wp_redirect(site_url());
      exit;

    } catch (Exception $e) {
      error_log('Error handling auth code: ' . $e->getMessage());
      wp_die('Error processing authorization code');
    }
  }


}