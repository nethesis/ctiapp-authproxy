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
            error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain}. Expected HTTP code 401, got $httpCode");
            return False;
        }

        // Step 2: Extract the nonce from the response header
        preg_match('/uthenticate: Digest ([0-9a-f]+)/', $response, $matches);

        if (!isset($matches[1])) {
            error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain}. No nonce found in response");
            return False;
        }
        
        $nonce = $matches[1];
        
        // Step 3: Build the authentication token
        $tohash = "$cloudUsername:$cloudPassword:$nonce";
        $token = hash_hmac('sha1', $tohash, $cloudPassword);
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true') error_log("DEBUG: Token generated for {$cloudUsername}@{$cloudDomain}");
    } else {
        // Password is already a token
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true') error_log("DEBUG: Password is already a token for {$cloudUsername}@{$cloudDomain}");
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

    // Step 5: check if lk is set and is valid
    if (isset($response['lkhash'])) {
        $url = getenv("VALIDATE_LK_URL");
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $headers = array("Authorization: Bearer ".$response['lkhash']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $lkcheck = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true') error_log("DEBUG: lkhash validated for {$cloudUsername}@{$cloudDomain}");
        if ($httpCode !== 200) {
            error_log("ERROR: Failed to validate lkhash for {$cloudUsername}@{$cloudDomain}. Expected HTTP code 200, got $httpCode");
            return false;
        }
    } else {
        error_log("ERROR: Missing lkhash in response for {$cloudUsername}@{$cloudDomain}");
        return false;
    }

    // Step 6: Return the sip credentials
    foreach ($response['endpoints']['extension'] as $extension) {
        if ($extension['type'] == 'mobile') {
            $sipUser = $extension['id'];
            $sipPassword = $extension['secret'];
            return [
                'sipUser' => $sipUser,
                'sipPassword' => $sipPassword,
                'nv8' => isset($response['profile']['macro_permissions']['nethvoice_cti']), // TODO remove when nethcti-server is updated
                'proxy_fqdn' => (isset($response['proxy_fqdn']) ? $response['proxy_fqdn'] : "")
            ];
        }
    }
    return false;
}

function handle($data) {
    if (!isset($data['username']) or !isset($data['password']) or !isset($data['token'])) {
        error_log("ERROR: Missing parameters. Expecrted username, password and token, got ".implode(',',array_keys($data)));
        return header('HTTP/1.1 400 Bad Request');
    }
    $token = getenv("TOKEN");
    if ($token != $data['token']) {
        error_log("ERROR: Invalid hardcoded token for {$data['username']}");
        return header('HTTP/1.1 401 Invalid Token');
    }
    $tmp = explode('@',trim(strtolower($data['username'])));
    $cloudUsername = $tmp[0];
    $cloudDomain = $tmp[1];
    if (isset($tmp[2]) && $tmp[2] === 'qrcode') {
        $isToken = true;
        $loginTypeString = "@qrcode";
        if(getenv('DEBUG') && $_ENV['DEBUG'] === 'true') error_log("DEBUG: Using qrcode login for {$cloudUsername}@{$cloudDomain}");
    } else {
        $isToken = false;
        $loginTypeString = "";
    }
    $cloudPassword = $data['password'];

    $result = getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken);

    if (!$result) {
        error_log("ERROR: Failed to get sip credentials for {$cloudUsername}@{$cloudDomain}");
        return header("HTTP/1.0 404 Not Found");
    }

    header("Content-type: text/xml");
    $proxy = "";
    if ($result['proxy_fqdn']) {
        $proxy = "<proxy>{$result['proxy_fqdn']}:5061</proxy>";
    } elseif ($result['nv8']) { // TODO remove when nethcti-server is updated
        $proxy = "<proxy>{$cloudDomain}:5061</proxy>";
    } else {
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true') error_log("DEBUG: No proxy fqdn found in response for {$cloudUsername}@{$cloudDomain}");
    }
    $out = "
<account>
  <cloud_username>{$cloudUsername}@{$cloudDomain}{$loginTypeString}</cloud_username>
  <cloud_password>{$cloudPassword}</cloud_password>
  <username>{$result['sipUser']}</username>
  <password>{$result['sipPassword']}</password>
  <extProvInterval>3600</extProvInterval>
  $proxy
  <host>{$cloudDomain}</host>
  <transport>tls+sip:</transport>
</account>
";
    echo $out;
    if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true') error_log('DEBUG: Returning sip credentials: '.preg_replace('/password>.*<\//','password>xxxx</',$out));
}

$jsonData = file_get_contents('php://input');
$data = json_decode($jsonData, true);
if ($data) {
    handle($data);
} else {
    error_log("ERROR: Invalid request: missing data");
    header('HTTP/1.1 400 Bad Request');
}
