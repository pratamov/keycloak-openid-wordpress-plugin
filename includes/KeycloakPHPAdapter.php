<?php
if (!isset($_SESSION)) {
    session_start();
}

class KeycloakPHPAdapter
{
	
	private $properties;
	private $userInfo;
	private $nonce;
	private $state;
	private $token;
	
	public function __construct(KeycloakProperties $properties) {
		
        $this->properties = $properties;
		
    }
	
	private function getRedirectURL() {

        if (property_exists($this, 'redirectURL') && $this->redirectURL) {
            return $this->redirectURL;
        }

        $protocol = @$_SERVER['HTTP_X_FORWARDED_PROTO'] 
                  ?: @$_SERVER['REQUEST_SCHEME']
                  ?: ((isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") ? "https" : "http");

        $port = @intval($_SERVER['HTTP_X_FORWARDED_PORT'])
              ?: @intval($_SERVER["SERVER_PORT"])
              ?: (($protocol === 'https') ? 443 : 80);

        $host = @explode(":", $_SERVER['HTTP_HOST'])[0]
              ?: @$_SERVER['SERVER_NAME']
              ?: @$_SERVER['SERVER_ADDR'];

        $port = ($protocol === 'https' && $port === 443) || ($protocol === 'http' && $port === 80) ? '' : ':' . $port;

        return sprintf('%s://%s%s/%s', $protocol, $host, $port, @trim(reset(explode("?", $_SERVER['REQUEST_URI'])), '/'));
		
    }
	
	private function generateRandString() {
		
        return md5(uniqid(rand(), TRUE));
		
    }
	
	private function setNonce() {
		
		$this->nonce = $this->generateRandString();
		$_SESSION['openid_connect_nonce'] = $this->nonce;
		
	}
	
	private function setState() {
		
		$this->state = $this->generateRandString();
		$_SESSION['openid_connect_state'] = $this->nonce;
		
	}
	
	private function post($url, $params, $headers = array()) {
		
		$ch = curl_init($url);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params, null, '&'));
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		
		$return = curl_exec($ch);
		$info = curl_getinfo($ch);
		
		curl_close($ch);
		
		return $return;
		
	}
	
	private function decodeToken($token, $section = 0) {

        $parts = explode(".", $token);
		$code = base64_decode(strtr($parts[$section], '-_,', '+/='));
        return json_decode($code);
		
    }
	
	private function decodeToken2($token, $section = 0) {

        $parts = explode(".", $token);
		$code = base64_decode($parts[$section]);
        return json_decode($code);
		
    }
	
	// STEP 1: Redirect to Keycloak login page and comeback with code
	private function step1() {
		
		$keycloakAuthServer = rtrim($this->properties->keycloakAuthServer, "/");
		$keycloakRealm = $this->properties->keycloakRealm;
		$url = $keycloakAuthServer . "/realms/" . $keycloakRealm . "/protocol/openid-connect/auth";
		
		$this->setNonce();
		$this->setState();
		
		$params = array(
			'response_type'	=> 'code',
			'redirect_uri'	=> $this->getRedirectURL(),
			'client_id'		=> $this->properties->keycloakResource,
			'nonce'			=> $this->nonce,
			'state'			=> $this->state,
			'scope'			=> 'openid'
		);
		
		$url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($params, null, '&');
		session_commit();
		get_header();
		wp_redirect($url);
		//header('Location: ' . $url);
		exit;
		
	}
	
	// Step 2: Request token
	private function step2() {
		
		$keycloakAuthServer = rtrim($this->properties->keycloakAuthServer, "/");
		$keycloakRealm = $this->properties->keycloakRealm;
		$url = $keycloakAuthServer . "/realms/" . $keycloakRealm . "/protocol/openid-connect/token";
		
		$params = array(
			'grant_type'	=> 'authorization_code',
			'code'			=> $_REQUEST["code"],
			'redirect_uri'	=> $this->getRedirectURL(),
			'client_id'		=> $this->properties->keycloakResource,
			'client_secret'	=> $this->properties->keycloakCredentialSecret
		);
		
		$token = $this->post($url, $params);
		return json_decode($token);
		
	}
	
	// Step 3: Retrieve User Data
	private function step3($token) {
		
		$keycloakAuthServer = rtrim($this->properties->keycloakAuthServer, "/");
		$keycloakRealm = $this->properties->keycloakRealm;
		$url = $keycloakAuthServer . "/realms/" . $keycloakRealm . "/protocol/openid-connect/userinfo";
		
		$headers = array (
			'Authorization: Bearer ' . $token->access_token
		);
		
		$userInfoObject = json_decode($this->post($url, array(), $headers));
		
		$this->userInfo = new UserInfo;
		
		$this->userInfo->sub					= isset($userInfoObject->sub) ? $userInfoObject->sub : "";
		$this->userInfo->name					= isset($userInfoObject->name) ? $userInfoObject->name : "";
		$this->userInfo->preferred_username		= isset($userInfoObject->preferred_username) ? $userInfoObject->preferred_username : "";
		$this->userInfo->given_name				= isset($userInfoObject->given_name) ? $userInfoObject->given_name : "";
		$this->userInfo->family_name			= isset($userInfoObject->family_name) ? $userInfoObject->family_name : "";
		$this->userInfo->email					= isset($userInfoObject->email) ? $userInfoObject->email : "";
		
		$_SESSION['sub'] = $this->userInfo->sub;
		
	}
	
	public function authenticate() {
		
		if (!isset($_REQUEST["code"])) {
			$this->step1();
		}
		else {
			$this->token = $this->step2();
			if (isset($this->token->id_token)) {
				$this->step3($this->token);
			}
			else {
				// if error, refresh the code
				$this->step1();
			}
		}
	}
	
	public function getAccessToken() {
		return $this->token->access_token;
	}
	
	public function getUserInfo() {
		return $this->userInfo;
	}
	
	public function isLoggedIn() {
		
		return isset($_SESSION['sub']);
		
	}
	
	public function logout($redirect) {
		
		unset($_SESSION['openid_connect_nonce']);
		unset($_SESSION['openid_connect_state']);
		unset($_SESSION['sub']);
		
		$keycloakAuthServer = rtrim($this->properties->keycloakAuthServer, "/");
		$keycloakRealm = $this->properties->keycloakRealm;
		$url = $keycloakAuthServer . "/realms/" . $keycloakRealm . "/protocol/openid-connect/logout";
		
		$params = array(
			'redirect_uri'				=> $redirect,
			'post_logout_redirect_uri'	=> $redirect
		);
		
		$url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($params, null, '&');
		session_commit();
		header('Location: ' . $url);
		exit;
		
    }
}