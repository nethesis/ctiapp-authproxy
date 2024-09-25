<?php
#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: AGPL-3.0
#

// function to make http GET requests
function makeRequest($username, $token, $url)
{
    // init curl
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    // set headers
    $headers = array("Authorization: $username:$token");
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    curl_close($ch);

    // read response
    $response = json_decode($response, true);

    // return response
    return $response;
}

// function get auth token
function getAuthToken($cloudUsername, $cloudPassword, $cloudDomain)
{
    // compose login url
    $authUrl = "https://$cloudDomain/webrest/authentication/login";
    $authData = "username=" . urlencode($cloudUsername) . "&password=" . urlencode($cloudPassword);

    // exec login
    $ch = curl_init($authUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $authData);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_HEADER, true);

    // get response
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    // close curl and read response
    curl_close($ch);
    if ($httpCode !== 401) {
        error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain}. Expected HTTP code 401, got $httpCode");
        return False;
    }

    // extract the nonce from the response header
    preg_match('/uthenticate: Digest ([0-9a-f]+)/', $response, $matches);

    // if nonce is empty, return error
    if (!isset($matches[1])) {
        error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain}. No nonce found in response");
        return False;
    }

    // read nonce
    $nonce = $matches[1];

    // build the authentication token
    $tohash = "$cloudUsername:$cloudPassword:$nonce";
    $token = hash_hmac('sha1', $tohash, $cloudPassword);

    return $token;
}

// login to cti using the cloud credentials and get the sip credentials using the /user/me API
function getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken = false)
{
    // Step 1: Authenticate and obtain the authentication token if isToken is false
    if (!$isToken) {
        // get auth token
        $token = getAuthToken($cloudUsername, $cloudPassword, $cloudDomain);

        // print debug log
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
            error_log("DEBUG: Token generated for {$cloudUsername}@{$cloudDomain}");
    } else {
        // print debug string
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
            error_log("DEBUG: Password is already a token for {$cloudUsername}@{$cloudDomain}");

        // assign password as token
        $token = $cloudPassword;
    }

    // Step 2: Make the request to user/me API
    $url = "https://$cloudDomain/webrest/user/me";

    // make response
    $response = makeRequest($cloudUsername, $token, $url);

    // Step 3: check if lk is set and is valid
    if (isset($response['lkhash'])) {
        // read api url from env
        $url = getenv("VALIDATE_LK_URL");

        // create curl state
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        // set headers
        $headers = array("Authorization: Bearer " . $response['lkhash']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        // exec curl
        $lkcheck = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // print debug string
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
            error_log("DEBUG: lkhash validated for {$cloudUsername}@{$cloudDomain}");

        // check if return code is 200, otherwise return false
        if ($httpCode !== 200) {
            error_log("ERROR: Failed to validate lkhash for {$cloudUsername}@{$cloudDomain}. Expected HTTP code 200, got $httpCode");
            return false;
        }
    } else {
        error_log("ERROR: Missing lkhash in response for {$cloudUsername}@{$cloudDomain}");
        return false;
    }

    // Step 4: Return the sip credentials
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

    // if step 4 has no endpoints, return false
    return false;
}

function handle($data)
{
    // check if username, password and token are set
    if (!isset($data['username']) or !isset($data['password']) or !isset($data['token'])) {
        error_log("ERROR: Missing parameters. Expected username, password and token, got " . implode(',', array_keys($data)));
        return header('HTTP/1.1 400 Bad Request');
    }

    // read TOKEN from env
    $token = getenv("TOKEN");

    // check if token is the same, otherwise return 401
    if ($token != $data['token']) {
        error_log("ERROR: Invalid hardcoded token for {$data['username']}");
        return header('HTTP/1.1 401 Invalid Token');
    }

    // extract domain from username
    $tmp = explode('@', trim(strtolower($data['username'])));
    $cloudUsername = $tmp[0];
    $cloudDomain = $tmp[1];

    // check if login is made with qrcode
    if (isset($tmp[2]) && $tmp[2] === 'qrcode') {
        $isToken = true;
        $loginTypeString = "@qrcode";

        // print debug log
        if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
            error_log("DEBUG: Using qrcode login for {$cloudUsername}@{$cloudDomain}");
    } else {
        $isToken = false;
        $loginTypeString = "";
    }

    // read password
    $cloudPassword = $data['password'];

    // check if app attribute is set
    if (isset($data['app'])) {
        // read app
        $app = $data['app'];

        // switch app case
        switch ($app) {
            // handle External Provisioning app
            case 'login':
                // get sip credentials with POST data
                $result = getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken);

                // check if sip credentials exists
                if (!$result) {
                    error_log("ERROR: Failed to get sip credentials for {$cloudUsername}@{$cloudDomain}");
                    return header("HTTP/1.0 404 Not Found");
                }

                // set headers
                header("Content-type: text/xml");

                // compose xml configuration string
                $proxy = "";
                if ($result['proxy_fqdn']) {
                    $proxy = "<proxy>{$result['proxy_fqdn']}:5061</proxy>";
                } elseif ($result['nv8']) { // TODO remove when nethcti-server is updated
                    $proxy = "<proxy>{$cloudDomain}:5061</proxy>";
                } else {
                    if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
                        error_log("DEBUG: No proxy fqdn found in response for {$cloudUsername}@{$cloudDomain}");
                }

                // compose final xml string
                $xmlConfString = "
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

                // return xml string
                echo $xmlConfString;

                // print debug string
                if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
                    error_log('DEBUG: Returning sip credentials: ' . preg_replace('/password>.*<\//', 'password>xxxx</', $xmlConfString));

                break;
            // handle Contact Sources app
            case 'contacts':
                // get auth token
                $token = getAuthToken($cloudUsername, $cloudPassword, $cloudDomain);

                // get phonebook counters
                $url = "https://$cloudDomain/webrest/phonebook/search/?offset=0&limit=1&view=all";

                // make request
                $response = makeRequest($cloudUsername, $token, $url);

                // read counter file
                $count = 0;
                if (file_exists('/tmp/phonebook_counters_' . $cloudDomain)) {
                    $count = file_get_contents('/tmp/phonebook_counters_' . $cloudDomain);
                }

                // get request headers
                $headers = apache_request_headers();

                // check if counter is equal, return 304 Not Modified
                if (isset($headers['If-Modified-Since']) && $count == $response['count']) {
                    if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
                        error_log('DEBUG: Phonebook contacts are the same: ' . $count);

                    // return header 304
                    header('HTTP/1.1 304 Not Modified; Last-Modified: ' . date(DATE_RFC2822));
                    return;
                }

                // new contacts found, write to log
                if (getenv('DEBUG') && $_ENV['DEBUG'] === 'true')
                    error_log('DEBUG: Phonebook new contacts found: ' . $response['count']);

                // make request to get all phonebook contacts
                $url = "https://$cloudDomain/webrest/phonebook/search/?view=all";

                // make request
                $response = makeRequest($cloudUsername, $token, $url);

                // create contacts object
                $contacts = array();

                // loop contacts api response
                foreach ($response['rows'] as $contact) {
                    // compose contacts object
                    $contacts[] = [
                        "avatar" => "",
                        "largeAvatar" => "",
                        "birthday" => "",
                        "checksum" => "",
                        "contactEntries" => [
                            [
                                "entryId" => "0",
                                "label" => "home phone",
                                "type" => "tel",
                                "uri" => $contact["homephone"]
                            ],
                            [
                                "entryId" => "1",
                                "label" => "work phone",
                                "type" => "tel",
                                "uri" => $contact["workphone"]
                            ],
                            [
                                "entryId" => "2",
                                "label" => "mobile",
                                "type" => "tel",
                                "uri" => $contact["cellphone"]
                            ],
                            [
                                "entryId" => "3",
                                "label" => "home email",
                                "type" => "email",
                                "uri" => $contact["homeemail"]
                            ],
                            [
                                "entryId" => "4",
                                "label" => "work email",
                                "type" => "email",
                                "uri" => $contact["workemail"]
                            ],
                        ],
                        "contactAddresses" => [
                            [
                                "addressId" => "0",
                                "label" => "home address",
                                "city" => $contact["homecity"],
                                "country" => $contact["homecountry"],
                                "countryCode" => "",
                                "state" => $contact["homeprovince"],
                                "street" => $contact["homestreet"],
                                "zip" => $contact["homepostalcode"]
                            ],
                            [
                                "addressId" => "1",
                                "label" => "work address",
                                "city" => $contact["workcity"],
                                "country" => $contact["workcountry"],
                                "countryCode" => "",
                                "state" => $contact["workprovince"],
                                "street" => $contact["workstreet"],
                                "zip" => $contact["workpostalcode"]
                            ]
                        ],
                        "contactId" => $contact["id"],
                        "company" => $contact["company"],
                        "displayName" => $contact["name"],
                        "fname" => "",
                        "lname" => "",
                        "notes" => $contact["notes"]
                    ];
                }

                // set counter in a file
                file_put_contents("/tmp/phonebook_counters_" . $cloudDomain, $response['count']);

                // set headers
                header("Content-type: application/json");
                header("Last-Modified: " . date(DATE_RFC2822));
                header('HTTP/1.1 200 OK');

                // print results
                $result = json_encode(array("contacts" => $contacts));
                echo $result;

                break;
            default:
                break;
        }
    }
}

// read json from input
$jsonData = file_get_contents('php://input');

// decode json
$data = json_decode($jsonData, true);

// check if data is set
if ($data) {
    // start request handle
    handle($data);
} else {
    // no data, return 400
    error_log("ERROR: Invalid request: missing data");
    header('HTTP/1.1 400 Bad Request');
}
