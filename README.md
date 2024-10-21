# WordPress Keycloak SSO Plugin

This plugin integrates Keycloak Single Sign-On (SSO) functionality into your WordPress site, allowing users to authenticate and manage their accounts through Keycloak.

## 1. Installation

You can install the plugin in two ways:

### a. Copy Plugin to WordPress
- Copy the plugin folder to your WordPress directory:  
  `wp-content/plugins`
- After copied, go to:  
  `WP Admin -> Plugins -> Installed Plugins -> Activate the Plugin`.
### b. Upload Zipped Plugin
- Zip the plugin directory.
- Navigate to your WordPress dashboard:  
  `wp-admin -> Plugins -> Add New -> Upload Plugin`.
- Select and upload the zipped plugin file.
- After uploading, go to:  
  `Plugins -> Installed Plugins -> Activate the Plugin`.

## 2. Configuration

Once installed, configure the plugin:

1. In the WordPress dashboard, go to:  
   `Settings -> Keycloak SSO`.

2. You will need to retrieve all necessary parameters from your Keycloak setup (such as `client ID`, `client secret`, and `redirect URI`), and fill them into the configuration fields.

## 3. Shortcodes

You can use the following shortcodes on any page to integrate Keycloak functionality:

- **Login Form:**  
  `[keycloak_login_form]`

- **Signup Form:**  
  `[keycloak_signup_form]`

- **Change Password Form:**  
  `[keycloak_change_password_form]`

- **Forgot Password Form:**  
  `[keycloak_forgot_password_form]`

- **Logout Form:**  
  `[keycloak_logout_form]`

These shortcodes will automatically handle the respective actions with Keycloak.
