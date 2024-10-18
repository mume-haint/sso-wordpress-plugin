<?php

class KeycloakShortcodes {
  private string $handle_auth_code_path = 'handle-auth-code';
  private string $realm;
  private string $client_id;
  private string $keycloak_url;
  private string $login_redirect_path;
  public function __construct($realm, $client_id, $keycloak_url, $login_redirect_path) {
    $this->realm = $realm;
    $this->client_id = $client_id;
    $this->keycloak_url = $keycloak_url;
    $this->login_redirect_path = $login_redirect_path;


    error_log('Add shortcode');
    add_shortcode('keycloak_login_form', array($this, 'login_form_shortcode'));
    add_shortcode('keycloak_signup_form', array($this, 'signup_form_shortcode'));
    add_shortcode('keycloak_change_password_form', array($this, 'change_password_form_shortcode'));
    add_shortcode('keycloak_forgot_password_form', array($this, 'forgot_password_form_shortcode'));
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
                        console.log(event.data.token)
                        window.location.href = '<?php echo site_url($this->login_redirect_path) ?>'
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
    <button id="keycloak-signup-btn">Signup with Keycloak</button>

    <script>
        jQuery(document).ready(function ($) {
            $('#keycloak-signup-btn').on('click', function (e) {
                e.preventDefault();

                var keycloakAuthUrl = '<?php echo $this->get_keycloak_signup_url(); ?>';
                console.log(keycloakAuthUrl)
                var popup = window.open(keycloakAuthUrl, 'keycloakSignup', 'width=600,height=700');

                if (!popup || popup.closed || typeof popup.closed == 'undefined') {
                    alert('Popup blocked! Please allow popups for this website.');
                    return;
                }
                window.addEventListener('message', function (event) {
                    if (event.origin !== window.location.origin) {
                        return;
                    }

                    if (event.data.status === 'logged_in') {
                        console.log(event.data.token)
                        window.location.href = '<?php echo site_url($this->login_redirect_path) ?>'
                    }
                }, false);
            });
        });
    </script>
    <?php
    return ob_get_clean();
  }

  public function change_password_form_shortcode() {
    ob_start();
    ?>
    <button id="keycloak-change-password-btn">Change password with Keycloak</button>

    <script>
        jQuery(document).ready(function ($) {
            $('#keycloak-change-password-btn').on('click', function (e) {
                e.preventDefault();

                var keycloakAuthUrl = '<?php echo $this->get_keycloak_change_password_url(); ?>';
                console.log(keycloakAuthUrl)
                var popup = window.open(keycloakAuthUrl, 'keycloakSignup', 'width=600,height=700');

                if (!popup || popup.closed || typeof popup.closed == 'undefined') {
                    alert('Popup blocked! Please allow popups for this website.');
                    return;
                }
                window.addEventListener('message', function (event) {
                    if (event.origin !== window.location.origin) {
                        return;
                    }

                    if (event.data.status === 'logged_in') {
                        console.log(event.data.token)
                        window.location.href = '<?php echo site_url($this->login_redirect_path) ?>'
                    }
                }, false);
            });
        });
    </script>
    <?php
    return ob_get_clean();
  }

  public function forgot_password_form_shortcode() {
    ob_start();
    ?>
    <button id="keycloak-forgot-password-btn">Forgot password with Keycloak</button>

    <script>
        jQuery(document).ready(function ($) {
            $('#keycloak-forgot-password-btn').on('click', function (e) {
                e.preventDefault();

                var keycloakAuthUrl = '<?php echo $this->get_keycloak_forgot_password_url(); ?>';
                console.log(keycloakAuthUrl)
                var popup = window.open(keycloakAuthUrl, 'keycloakSignup', 'width=600,height=700');

                if (!popup || popup.closed || typeof popup.closed == 'undefined') {
                    alert('Popup blocked! Please allow popups for this website.');
                    return;
                }
                window.addEventListener('message', function (event) {
                    if (event.origin !== window.location.origin) {
                        return;
                    }

                    if (event.data.status === 'logged_in') {
                        console.log(event.data.token)
                        window.location.href = '<?php echo site_url($this->login_redirect_path) ?>'
                    }
                }, false);
            });
        });
    </script>
    <?php
    return ob_get_clean();
  }

  private function get_keycloak_auth_url() {
    $redirect_uri = site_url($this->handle_auth_code_path);
    $state = bin2hex(random_bytes(16));

    // Construct the authorization URL
    $auth_url = "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/auth";
    $auth_url .= '?response_type=code';
    $auth_url .= '&client_id=' . urlencode($this->client_id);
    $auth_url .= '&redirect_uri=' . urlencode($redirect_uri);
    $auth_url .= '&scope=' . urlencode('openid profile email');
    $auth_url .= '&state=' . urlencode($state);

    return $auth_url;
  }

  private function get_keycloak_signup_url() {
    $redirect_uri = site_url($this->handle_auth_code_path);

    // Construct the authorization URL
    $auth_url = "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/registrations";
    $auth_url .= '?response_type=code';
    $auth_url .= '&client_id=' . urlencode($this->client_id);
    $auth_url .= '&redirect_uri=' . urlencode($redirect_uri);
    $auth_url .= '&scope=' . urlencode('openid profile');

    return $auth_url;
  }

  private function get_keycloak_change_password_url() {
    $redirect_uri = site_url($this->handle_auth_code_path);

    // Construct the authorization URL
    $auth_url = "{$this->keycloak_url}/realms/{$this->realm}/protocol/openid-connect/auth";
    $auth_url .= '?response_type=code';
    $auth_url .= '&client_id=' . urlencode($this->client_id);
    $auth_url .= '&redirect_uri=' . urlencode($redirect_uri);
    $auth_url .= '&scope=' . urlencode('openid');
    $auth_url .= '&kc_action=' . 'UPDATE_PASSWORD';

    return $auth_url;
  }

  private function get_keycloak_forgot_password_url() {
    $redirect_uri = site_url($this->handle_auth_code_path);

    // Construct the authorization URL
    $auth_url = "{$this->keycloak_url}/realms/{$this->realm}/login-actions/reset-credentials";
    $auth_url .= '?response_type=code';
    $auth_url .= '&client_id=' . urlencode($this->client_id);
    $auth_url .= '&redirect_uri=' . urlencode($redirect_uri);
    $auth_url .= '&scope=' . urlencode('openid');

    return $auth_url;
  }
}
