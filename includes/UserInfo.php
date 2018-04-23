<?php
if (!isset($_SESSION)) {
    session_start();
}

class UserInfo
{
	public $sub;
	public $name;
	public $preferred_username;
	public $given_name;
	public $family_name;
	public $email;
}