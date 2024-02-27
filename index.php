<?php
#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: AGPL-3.0
#

// login to cti using the cloud credentials and get the sip credentials using the /user/me API
function getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken = false) {
    // Step 1: Authenticate and obtain the authentication token if isToken is false
    if (!$isToken) {
        $authUrl = "https://$cloudDomain/webrest/authentication/login";
        $authData = "username=".urlencode($cloudUsername)."&password=".urlencode($cloudPassword);
    
        $ch = curl_init($authUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $authData);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HEADER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        if ($httpCode !== 401) {
            return False;
        }

        // Step 2: Extract the nonce from the response header
        preg_match('/uthenticate: Digest ([0-9a-f]+)/', $response, $matches);

        if (!isset($matches[1])) {
            return False;
        }
        
        $nonce = $matches[1];
        
        // Step 3: Build the authentication token
        $tohash = "$cloudUsername:$cloudPassword:$nonce";
        $token = hash_hmac('sha1', $tohash, $cloudPassword);
    } else {
        // Password is already a token
        $token = $cloudPassword;
    }
    // Step 4: Make the request to user/me API
    $url = "https://$cloudDomain/webrest/user/me";

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    $headers = array("Authorization: $cloudUsername:$token");
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $response = json_decode($response, true);

    // get the sip credentials from the response
    foreach ($response['endpoints']['extension'] as $extension) {
        if ($extension['type'] == 'mobile') {
            $sipUser = $extension['id'];
            $sipPassword = $extension['secret'];
            return [
                'sipUser' => $sipUser,
                'sipPassword' => $sipPassword,
                'nv8' => isset($response['profile']['macro_permissions']['nethvoice_cti']),
                'token' => $token,
            ];
        }
    }
    return false;
}

function handle($data) {
    if (!isset($data['username']) or !isset($data['password']) or !isset($data['token'])) {
        return header('HTTP/1.1 400 Bad Request');
    }
    $token = getenv("TOKEN");
    if ($token != $data['token']) {
        return header('HTTP/1.1 401 Invalid Token');
    }
    $tmp = explode('@',trim(strtolower($data['username'])));
    $cloudUsername = $tmp[0];
    $cloudDomain = $tmp[1];
    if (isset($tmp[2]) && $tmp[2] === 'qrcode') {
        $isToken = true;
    } else {
        $isToken = false;
    }
    $cloudPassword = $data['password'];

    $result = getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken);

    if (!$result) {
        return header("HTTP/1.0 404 Not Found");
    }

    header("Content-type: text/xml");
    $proxy = "";
    if ($result['nv8']) {
        $proxy = "<proxy>{$cloudDomain}:5061</proxy>";
    }
    $out = "
<account>
  <cloud_username>{$cloudUsername}@{$cloudDomain}@qrcode</cloud_username>
  <cloud_password>{$result['token']}</cloud_password>
  <username>{$result['sipUser']}</username>
  <password>{$result['sipPassword']}</password>
  <extProvInterval>3600</extProvInterval>
  $proxy
  <host>{$cloudDomain}</host>
  <transport>tls+sip:</transport>
</account>
";
    echo $out;
}

$jsonData = file_get_contents('php://input');
$data = json_decode($jsonData, true);
if ($data) {
    handle($data);
} else {
    header('HTTP/1.1 400 Bad Request');
}
