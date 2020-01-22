#!/usr/bin/php
<?php

// this script takes alert posts from voipmonitor and via netsapiens SNAPsolution API will change user permissions

// fill out the info below 
define("SERVER", "server-fqdn");
define("SUPERUSER", "superuser");
define("PASSWORD", "password");
define("CLIENTID", "client-id");
define("CLIENTSECRET", "secret");
define("NEWPERMISSION","Deny All");
define("ERRORMAILTO","user@domain.tld");

// parse data from voipmonitor
$triggeredRules = json_decode($argv[4],true);
$triggeredRules1=$triggeredRules['agregations'][0]['price_data'];

// Get a new Access token to given server
$query = array(
        'grant_type'    => 'password',
        'username'        => SUPERUSER,
        'password'        => PASSWORD,
        'client_id'        => CLIENTID,
        'client_secret'        => CLIENTSECRET,
);

$postFields = http_build_query($query);
$http_response = "";
$curl_result = __doCurl("https://".SERVER."/ns-api/oauth2/token", CURLOPT_POST, NULL, NULL, $postFields, $http_response);
if (!$curl_result){
    mail(ERRORMAILTO,"qos script error","The QoS billing script was unable to get an API access key, dial permissions will not be updated until this is fixed.");
    exit;
}
$token = json_decode($curl_result, /*assoc*/true);
if (!isset($token['access_token'])) {
    mail(ERRORMAILTO,"qos script error","The QoS billing script was unable to get an API access key, dial permissions will not be updated until this is fixed.");
    exit;
}
$token = $token['access_token'];


// iterate over domains
foreach ( $triggeredRules1 as $rule ) {

    if (array_key_exists("new_price",$rule))
    {
        $domain=$rule['domain'];

        // Get user List from domain
        $query = array(
                'object'	=> 'subscriber',
                'action'	=> "read",
                'domain'	=> $domain,
                'format'    =>  'json',
        );
        $userList = __doCurl("https://".SERVER."/ns-api/", CURLOPT_POST, "Authorization: Bearer " . $token, $query, null, $http_response);
        $userList = json_decode($userList,true);

        // iterate over users in the domain
        foreach ($userList as $array) {

            $user = $array['user'];

            // change permissions
            $query = array(
                'object' => 'subscriber',
                'action' => 'update',
                'user' => $user,
                'dial_policy' => NEWPERMISSION,
                'domain' => $domain,
            );
            
            __doCurl("https://".SERVER."/ns-api/", CURLOPT_POST, "Authorization: Bearer " . $token, $query, null, $http_response);

        }
   }
}

function __doCurl($url, $method, $authorization, $query, $postFields, &$http_response)
{
    $start= microtime(true);
    $curl_options = array(
            CURLOPT_URL => $url . ($query ? '?' . http_build_query($query) : ''),
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FORBID_REUSE => true,
            CURLOPT_TIMEOUT => 60
    );
    $headers = array();
    if ($authorization != NULL)
    {
        if ("bus:bus" == $authorization)
            $curl_options[CURLOPT_USERPWD]=$authorization;
        else
            $headers[$authorization]=$authorization;
    }
    $curl_options[$method] = true;
    if ($postFields != NULL )
    {
        $curl_options[CURLOPT_POSTFIELDS] = $postFields;
    }
    if (sizeof($headers)>0)
        $curl_options[CURLOPT_HTTPHEADER] = $headers;
    $curl_handle = curl_init();
    curl_setopt_array($curl_handle, $curl_options);
    $curl_result = curl_exec($curl_handle);
    $http_response = curl_getinfo($curl_handle, CURLINFO_HTTP_CODE);
    //print_r($http_response);
    curl_close($curl_handle);
    $end = microtime(true);
    if (!$curl_result)
        return NULL;
    else if ($http_response >= 400)
        return NULL;
    else
        return $curl_result;
}
?>

