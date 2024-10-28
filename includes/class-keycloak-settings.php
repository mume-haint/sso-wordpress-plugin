<?php

class KeycloakSettings
{
  public function __construct()
  {
    add_action('admin_menu', array($this, 'add_admin_menu'));
    add_action('admin_init', array($this, 'register_settings'));
  }

  public function add_admin_menu() {
    add_options_page(
      'Keycloak SSO Settings',
      'Keycloak SSO',
      'manage_options',
      'keycloak_sso',
      array($this, 'settings_page')
    );
  }

  public function register_settings() {
    // Register settings
    register_setting('keycloak_sso_settings_group', 'keycloak_client_id');
//    register_setting('keycloak_sso_settings_group', 'keycloak_client_secret');
    register_setting('keycloak_sso_settings_group', 'keycloak_url');
    register_setting('keycloak_sso_settings_group', 'keycloak_realm');
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
            <td>
              <input type="text" name="keycloak_client_id" value="<?php echo esc_attr(get_option('keycloak_client_id')); ?>" style="width: 400px;" placeholder="Ex: keycloak_client_id" />
              <p style="font-size: 14px; margin-top: 5px;">* Client must be of type <strong>public</strong> because this plugin uses the keycloak-javascript-adapter, which does not support client_secret.</p>
            </td>
          </tr>
<!--          <tr valign="top">-->
<!--            <th scope="row">Client Secret</th>-->
<!--            <td>-->
<!--              <div style="position: relative; width: 400px;">-->
<!--                <input type="password" name="keycloak_client_secret" id="keycloak_client_secret" value="--><?php //echo esc_attr(get_option('keycloak_client_secret')); ?><!--" style="width: 400px; padding-right: 30px;" />-->
<!--                <span id="toggleClientSecret" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer;" onclick="toggleClientSecretVisibility()">-->
<!--                👁️-->
<!--            </span>-->
<!--              </div>-->
<!--            </td>-->
<!--          </tr>-->
          <tr valign="top">
            <th scope="row">Keycloak URL</th>
            <td>
              <input type="text" name="keycloak_url" value="<?php echo esc_attr(get_option('keycloak_url')); ?>" style="width: 400px;" placeholder="Ex: https://keycloak_url" />
              <p style="font-size: 14px; margin-top: 5px;">* Keycloak must use <strong>HTTPS</strong> due to secure context requirements in the keycloak-js-adapter package.</p>
            </td>
          </tr>
          <tr valign="top">
            <th scope="row">Realm</th>
            <td><input type="text" name="keycloak_realm" value="<?php echo esc_attr(get_option('keycloak_realm')); ?>" style="width: 400px;" placeholder="Ex: keycloak_realm" /></td>
          </tr>
          <tr valign="top">
            <th scope="row">Login Redirect Path</th>
            <td><input type="text" name="keycloak_login_redirect_path" value="<?php echo esc_attr(get_option('keycloak_login_redirect_path')); ?>" style="width: 400px;" placeholder="/" /></td>
          </tr>
        </table>
        <?php submit_button(); ?>
      </form>
    </div>

<!--    <script type="text/javascript">-->
<!--        function toggleClientSecretVisibility() {-->
<!--            var input = document.getElementById('keycloak_client_secret');-->
<!--            var toggleIcon = document.getElementById('toggleClientSecret');-->
<!--            if (input.type === 'password') {-->
<!--                input.type = 'text';-->
<!--                toggleIcon.innerText = '🙈';-->
<!--            } else {-->
<!--                input.type = 'password';-->
<!--                toggleIcon.innerText = '👁️';-->
<!--            }-->
<!--        }-->
<!--    </script>-->
    <?php
  }
}