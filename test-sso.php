<?php
/*
Plugin Name: Test SSO
Description: Integrates Keycloak SSO into WordPress using OpenID Connect (Multi-site Support) with Signup Feature
Version: 1.2
Author: haint (Updated by Assistant)
*/

require __DIR__ . '/vendor/autoload.php';

require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-auth.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-shortcodes.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-settings.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-keycloak-sso-integration.php';

if (class_exists('KeycloakSSOIntegration')) {
  new KeycloakSSOIntegration();
}
