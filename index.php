<?php
#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: AGPL-3.0
#

// Set PHP configuration for large contact processing
ini_set('max_execution_time', 90);
ini_set('memory_limit', '512M');

// function to print debug log messages
function debug($message, $domain = null)
{
    // print debug if env is set
    if (getenv('DEBUG') && getenv('DEBUG') === 'true') {
        $prefix = $domain ? "DEBUG[$domain]: " : "DEBUG: ";
        error_log($prefix . $message);
    }
}

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
    $jsonResponse = json_decode($response, true);

    // Check if JSON decoding was successful
    if ($jsonResponse === null && json_last_error() !== JSON_ERROR_NONE) {
        error_log("ERROR: Failed to decode JSON: " . json_last_error_msg());
        debug("Response: " . $response);
        return false;
    }

    // return response
    return $jsonResponse;
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

    // Add error handling for curl execution
    if ($response === false) {
        error_log("ERROR: cURL error during authentication: " . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    // close curl and read response
    curl_close($ch);
    if ($httpCode !== 401) {
        error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain}. Expected HTTP code 401, got $httpCode");
        return false;
    }

    // extract the nonce from the response header
    preg_match('/uthenticate: Digest ([0-9a-f]+)/', $response, $matches);

    // if nonce is empty, return error
    if (!isset($matches[1])) {
        error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain}. No nonce found in response");
        return false;
    }

    // read nonce
    $nonce = $matches[1];

    // build the authentication token
    $tohash = "$cloudUsername:$cloudPassword:$nonce";
    $token = hash_hmac('sha1', $tohash, $cloudPassword);

    // print debug
    debug("Token generated for {$cloudUsername}", $cloudDomain);

    return $token;
}

// login to cti using the cloud credentials and get the sip credentials using the /user/me API
function getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken = false)
{
    // Step 1: Authenticate and obtain the authentication token if isToken is false
    if (!$isToken) {
        // get auth token
        $token = getAuthToken($cloudUsername, $cloudPassword, $cloudDomain);

        // print debug
        debug("Token generated for {$cloudUsername}", $cloudDomain);
    } else {
        // print debug
        debug("Password is already a token for {$cloudUsername}", $cloudDomain);

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

        // print debug
        debug("lkhash validated for {$cloudUsername}", $cloudDomain);

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
                'proxy_fqdn' => (isset($response['proxy_fqdn']) ? $response['proxy_fqdn'] : "")
            ];
        }
    }

    // if step 4 has no endpoints, return false
    debug("No endpoints found for {$cloudUsername}", $cloudDomain);
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

        // print debug
        debug("Using qrcode login for {$cloudUsername}", $cloudDomain);
    } else {
        $isToken = false;
        $loginTypeString = "";
    }

    // read password
    $cloudPassword = $data['password'];

    // check if app attribute is set, otherwise set login
    if (!isset($data['app'])) {
        $app = 'login';
    } else {
        // read app
        $app = $data['app'];
    }

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

            // check auth token
            if (!$isToken) {
                // get auth token
                $token = getAuthToken($cloudUsername, $cloudPassword, $cloudDomain);

                // print debug
                debug("Token generated for {$cloudUsername}", $cloudDomain);
            } else {
                // print debug
                debug("Password is already a token for {$cloudUsername}", $cloudDomain);

                // assign password as token
                $token = $cloudPassword;
            }

            // get busy lamp extensions
            $url = "https://$cloudDomain/webrest/user/endpoints/all";

            // make request
            $response = makeRequest($cloudUsername, $token, $url);

            // create busy lamp extensions object
            $busylamps = array();

            // loop busy lamp extensions api response
            foreach ($response as $username) {
                // get main extension as busylamp
                $busylamp = $username['endpoints']['mainextension'][0]['id'];

                // compose xml structure
                $busylamps[] = '<uri>' . $busylamp . '</uri>';
            }

            // set headers
            header("Content-type: text/xml");

            // compose xml configuration string
            $proxy = "";
            if ($result['proxy_fqdn']) {
                $proxy = "<proxy>{$result['proxy_fqdn']}:5061</proxy>";
            } else {
                // print debug
                debug("No proxy fqdn found in response for {$cloudUsername}", $cloudDomain);
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
                    <blf>" . implode("", $busylamps) . "</blf>
                    </account>
                    ";

            // return xml string
            echo $xmlConfString;

            // print debug
            debug('Returning sip credentials: ' . preg_replace('/password>.*<\//', 'password>xxxx</', $xmlConfString));

            break;
        // handle Contact Sources app
        case 'contacts':
            debug("Starting optimized contacts processing for {$cloudUsername}", $cloudDomain);

            // debug all request headers to understand cache behavior
            $allHeaders = apache_request_headers();
            debug("ALL REQUEST HEADERS: " . json_encode($allHeaders), $cloudDomain);

            // get auth token
            if (!$isToken) {
                // get auth token
                $token = getAuthToken($cloudUsername, $cloudPassword, $cloudDomain);

                // print debug
                debug("Contacts. Token generated for {$cloudUsername}", $cloudDomain);
            } else {
                // print debug
                debug("Contacts. Password is already a token for {$cloudUsername}", $cloudDomain);

                // assign password as token
                $token = $cloudPassword;
            }

            // get phonebook counters
            $url = "https://$cloudDomain/webrest/phonebook/search/?offset=0&limit=1&view=all";

            // make request
            $response = makeRequest($cloudUsername, $token, $url);

            if ($response == false) {
                debug("ERROR: Failed to get phonebook contacts for {$cloudUsername}", $cloudDomain);
                header("HTTP/1.0 404 Not Found");
                return;
            }

            // read counter file
            $count = 0;
            if (file_exists('/tmp/phonebook_counters_' . $cloudDomain)) {
                $count = file_get_contents('/tmp/phonebook_counters_' . $cloudDomain);
            }

            // get request headers
            $headers = apache_request_headers();

            // debug cache headers
            debug("Cache check - If-Modified-Since: " . (isset($headers['If-Modified-Since']) ? $headers['If-Modified-Since'] : 'NOT SET'), $cloudDomain);
            debug("Cache check - Current count: {$response['count']}, Cached count: $count", $cloudDomain);

            // check if client has cache AND counter is equal, return 304 Not Modified
            if (isset($headers['If-Modified-Since']) && $count == $response['count'] && $count > 0) {
                // print debug
                debug('Phonebook contacts are the same: ' . $count . ' - returning 304 Not Modified', $cloudDomain);

                // return 304 with proper headers
                header("Content-type: application/json");
                header("Last-Modified: " . date(DATE_RFC2822));
                header("Cache-Control: private, must-revalidate");
                header('HTTP/1.1 304 Not Modified');
                return;
            }

            // get total contacts count
            $totalContacts = $response['count'];

            debug("Phonebook contacts found: $totalContacts - fetching all contacts", $cloudDomain);

            // set counter in a file
            file_put_contents("/tmp/phonebook_counters_" . $cloudDomain, $totalContacts);

            // build complete contacts array
            $allContacts = [];
            $chunkSize = 2000;
            $offset = 0;

            $chunkNumber = 1;
            $totalChunks = ceil($totalContacts / $chunkSize);
            $startTime = microtime(true);

            while ($offset < $totalContacts) {
                $url = "https://$cloudDomain/webrest/phonebook/search/?view=all&limit=$chunkSize&offset=$offset";

                debug("Fetching page $chunkNumber/$totalChunks (offset $offset)", $cloudDomain);

                $chunkResponse = makeRequest($cloudUsername, $token, $url);

                if ($chunkResponse === false || !isset($chunkResponse['rows'])) {
                    debug("ERROR: Failed to get phonebook page at offset $offset for {$cloudUsername}", $cloudDomain);
                    break;
                }

                $chunkCount = count($chunkResponse['rows']);
                debug("Page $chunkNumber/$totalChunks completed: $chunkCount contacts fetched", $cloudDomain);

                // process contacts from current page
                foreach ($chunkResponse['rows'] as $contact) {
                    // compose contact object
                    $contactData = [
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

                    // add to contacts array
                    $allContacts[] = $contactData;
                }

                $offset += $chunkSize;
                $chunkNumber++;
                unset($chunkResponse);

                if (count($allContacts) % 10000 === 0) {
                    gc_collect_cycles();
                    debug("Memory cleanup at " . count($allContacts) . " contacts - Memory: " . round(memory_get_usage(true) / 1024 / 1024, 1) . "MB", $cloudDomain);
                }
            }

            $totalTime = round((microtime(true) - $startTime) * 1000, 0);
            debug("Contacts fetched: " . count($allContacts) . " contacts in {$totalTime}ms", $cloudDomain);

            header("Content-type: application/json");
            header("Last-Modified: " . date(DATE_RFC2822));
            header("Cache-Control: private, must-revalidate");
            header('HTTP/1.1 200 OK');

            $finalResponse = ['contacts' => $allContacts];
            echo json_encode($finalResponse);

            debug("Completed contacts processing for {$cloudUsername} - " . count($allContacts) . " contacts sent", $cloudDomain);

            break;
        case 'quickdial':
            // get auth token
            if (!$isToken) {
                // get auth token
                $token = getAuthToken($cloudUsername, $cloudPassword, $cloudDomain);

                // print debug
                debug("QuickDials. Token generated for {$cloudUsername}", $cloudDomain);
            } else {
                // print debug
                debug("QuickDials. Password is already a token for {$cloudUsername}", $cloudDomain);

                // assign password as token
                $token = $cloudPassword;
            }

            // get quick dials
            $url = "https://$cloudDomain/webrest/phonebook/speeddials";

            // make request
            $response = makeRequest($cloudUsername, $token, $url);

            // create quickdials object
            $quickdials = array();

            // create favorite list
            $favorites = array();

            // loop quickdials api response
            if (is_array($response)) {
                foreach ($response as $quickdial) {
                    // check if type is speeddial-favorite
                    if ($quickdial['notes'] == 'speeddial-favorite') {
                        // compose xml structure
                        $quickdials[] = '<item id="' . $quickdial['speeddial_num'] . '"><displayName>' . $quickdial['company'] . '</displayName><uri>' . $quickdial['speeddial_num'] . '</uri></item>';

                        // add favorite num to list, useful to check extensions to remove from list
                        $favorites[] = $quickdial['speeddial_num'];

                        // print debug message
                        debug("Quick dials is a favorite: " . $quickdial['company'] . " " . $quickdial['speeddial_num'], $cloudDomain);
                    }
                }
            }

            // get all extensions
            $url = "https://$cloudDomain/webrest/astproxy/extensions";

            // make request
            $response = makeRequest($cloudUsername, $token, $url);

            // create remove keys
            $removes = array();

            // get keys of response
            if (is_array($response)) {
                $extensions = array_keys($response);

                // loop extensions to remove
                foreach ($extensions as $extension) {
                    if (!in_array($extension, $favorites)) {
                        // compose xml structure
                        $removes[] = '<item id="' . $extension . '" action="remove"/>';

                        // print debug message
                        debug("Quick dials is not a favorite: " . $extension, $cloudDomain);
                    }
                }
            }

            // set header
            header("Content-type: text/xml");
            header('HTTP/1.1 200 OK');

            // print results
            echo '<root><quickDial>' . implode("", $quickdials) . implode("", $removes) . '</quickDial></root>';

            break;
        default:
            break;
    }
}

// Check if this is a healthcheck request
if ($_SERVER['REQUEST_URI'] === '/index.php/healthcheck') {
    header('HTTP/1.1 200 OK');
    exit;
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
