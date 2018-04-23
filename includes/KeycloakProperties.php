<?php
if (!isset($_SESSION)) {
    session_start();
}

class KeycloakProperties
{
	public $keycloakAuthServer			= 'https://kerjaindonesia.id:8443/auth';
	public $keycloakRealm				= 'arkademy';
	public $keycloakResource			= 'client-bahaso';
	public $keycloakCredentialSecret	= '7931337e-45fc-42da-a95f-477346126c8d';
	public $keycloakAuthRoles			= 'student';
}