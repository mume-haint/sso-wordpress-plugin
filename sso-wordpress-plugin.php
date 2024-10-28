<?php
/*
Plugin Name: SSO Wordpress plugin
Description: Integrates Keycloak SSO into WordPress using OpenID Connect (Multi-site Support) with Signup Feature
Version: 1.2
Author: haint (Updated by Assistant)
*/

if (!defined('ABSPATH')) {
  exit;
}

require __DIR__ . '/vendor/autoload.php';

require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-auth.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-shortcodes.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-settings.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-sso-integration.php';

if (class_exists('KeycloakSSOIntegration')) {
  new KeycloakSSOIntegration();
}

register_uninstall_hook(__FILE__, 'keycloak_sso_uninstall');

/**
 * Function to run on plugin uninstall.
 * Deletes plugin-related options from the database.
 */
function keycloak_sso_uninstall() {
  delete_option('keycloak_client_id');
//  delete_option('keycloak_client_secret');
  delete_option('keycloak_url');
  delete_option('keycloak_realm');
  delete_option('keycloak_login_redirect_path');
}

add_action('wp_enqueue_scripts','sso_js_init_key');
function sso_js_init_key()
{
  wp_register_script( 'keycloak-wp-js-key', plugins_url( '/js/keycloak-wp-key.js', __FILE__ ));
  wp_localize_script( 'keycloak-wp-js-key', 'ssoData', array(
    'keycloak_url' => get_option('keycloak_url'),
    'keycloak_client_id' => get_option('keycloak_client_id'),
    'keycloak_realm' => get_option('keycloak_realm')
  ));
  wp_enqueue_script( 'keycloak-wp-js-key' );
}

add_action('wp_enqueue_scripts','sso_js_init');

function sso_js_init() {
  wp_enqueue_script_module( 'keycloak-wp-js', plugins_url( '/js/keycloak-wp.js', __FILE__ ));
}
