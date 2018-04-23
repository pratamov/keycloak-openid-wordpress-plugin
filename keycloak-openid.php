<?php
/*
Plugin Name: Keycloak OpenID Connector
Plugin URI: https://github.com/pratamov/keycloak-openid-plugin
Description:  Connect to an OpenID Connect generic client using Authorization Code Flow
Version: 0.0.1
Author: Andre Pratama
Author URI: https://github.com/pratamov/keycloak-openid-plugin
License: GPLv2
*/

require 'includes/KeycloakProperties.php';
require 'includes/UserInfo.php';
require 'includes/KeycloakPHPAdapter.php';

function get_properties(){
	$properties = new KeycloakProperties;
	$properties->keycloakAuthServer			= 'https://kerjaindonesia.id:8443/auth';
	$properties->keycloakRealm				= 'arkademy';
	$properties->keycloakResource			= 'client-wordpress';
	$properties->keycloakCredentialSecret	= '7931337e-45fc-42da-a95f-477346126c8d';
	$properties->keycloakAuthRoles			= 'student';
	return $properties;
}

function authenticate(){
	$properties = get_properties();
	$adapter = new KeycloakPHPAdapter($properties);
	$adapter->authenticate();
}

function logout(){
	$properties = get_properties();
	$adapter = new KeycloakPHPAdapter($properties);
	$adapter->logout(get_home_url());
}

function test(){
	echo get_home_url();
}

function app_output_buffer() {
	ob_start();
}

add_action('init', 'app_output_buffer');
add_shortcode('keycloak_authenticate','authenticate');
add_shortcode('keycloak_logout','logout');