<?php

function essdn_to_username($essdn)
{
	require_once "db.php";

	$sub_pos = stripos($essdn, "/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=");
	if ($sub_pos === false) {
		return NULL;
	}
	$sub_pos += 69;
	$tmp_string = substr($essdn, $sub_pos);
	$sub_pos = strpos($tmp_string, '-');
	if ($sub_pos != 16) {
		return NULL;
	}
	$essdn_local = substr($tmp_string, $sub_pos + 1);
	$hex_string = substr($tmp_string, 8, 8);
	$hex = hex2bin($hex_string);
	$array = unpack("Vuid", $hex);
	if (!$array || !$array['uid']) {
		return NULL;
	}
	$info = get_user_info_by_id($array['uid']);
	if (!$info) {
		return NULL;
	}
	$at_pos = strpos($info['username'], '@');
	$address_part = substr($info['username'], 0, $at_pos);
	if (0 != strcasecmp($essdn_local, $address_part)) {
		return NULL;
	}
	return $info;
}

function username_to_essdn($info)
{
	require_once "conf.php";
	
	$config = get_app_config();
	$db_config = $config['exchange'];
	if (!isset($db_config)) {
		die("cannot find [exchange] section in config file");
	}
	if (!isset($db_config['orgnization'])) {
		die("cannot find orgnization under [exchange] in config file");
	}
	$essdn = "/o=" . $db_config['orgnization'] . "/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=";
	$int_bytes = pack("V", $info['did']);
	$essdn .= bin2hex($int_bytes);
	$int_bytes = pack("V", $info['uid']);
	$essdn .= bin2hex($int_bytes);
	$at_pos = strpos($info['username'], '@');
	$address_part = substr($info['username'], 0, $at_pos);
	$essdn .= "-" . $address_part;
	return $essdn;
}

function random_guid_string()
{
	return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
		mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535),
		mt_rand(16384, 20479), mt_rand(32768, 49151),
		mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
}

function get_user_server_guid($info)
{
	$username = $info['username'];
	$int_bytes = pack("V", $info['uid']);
	$hex_string = bin2hex($int_bytes);
	return sprintf('%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%s',
				ord($username[0]), ord($username[1]), ord($username[2]),
				ord($username[3]), ord($username[4]), ord($username[5]),
				ord($username[6]), ord($username[7]), ord($username[8]),
				ord($username[9]), ord($username[10]), ord($username[11]),
				$hex_string);
}

function get_server_dn($server_name)
{
	$config = get_app_config();
	$db_config = $config['exchange'];
	if (!isset($db_config)) {
		die("cannot find [exchange] section in config file");
	}
	if (!isset($db_config['orgnization'])) {
		die("cannot find orgnization under [exchange] in config file");
	}
	$essdn = "/o=" . $db_config['orgnization'] . "/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=" . $server_name;
	return $essdn;
}

function get_mdb_dn($server_name)
{
	return get_server_dn($server_name) . "/cn=Microsoft Private MDB";
}

function get_default_hostname()
{
	$config = get_app_config();
	$db_config = $config['exchange'];
	if (!isset($db_config)) {
		die("cannot find [exchange] section in config file");
	}
	if (!isset($db_config['hostname'])) {
		return $_SERVER['SERVER_NAME'];
	}
	return $db_config['hostname'];
}

function get_user_http_proxy($maildir, $host_name)
{
	$config = get_app_config();
	$http_proxy = $config['http-porxy'];
	if (!isset($http_proxy)) {
		return $host_name;
	}
	foreach ($http_proxy as $dir_prefix => $server_name) {
		if (0 === strpos($maildir, $dir_prefix) && '/' == $maildir[strlen($dir_prefix)]) {
			return $server_name;
		}
	}
	return $host_name;
}


?>