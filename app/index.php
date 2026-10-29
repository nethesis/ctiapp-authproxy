<?php
#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: AGPL-3.0
#

// function to print debug log messages
function debug($message, $domain = null)
{
    // print debug if env is set
    if (getenv('DEBUG') && getenv('DEBUG') === 'true') {
        if ($domain) {
            error_log("DEBUG[$domain]: " . $message);
        } else {
            error_log("DEBUG: " . $message);
        }
    }
}

// function to make authenticated HTTP requests
// $httpCode is filled with the HTTP status code of the response
// (stays 0 if the request fails at network level)
function makeRequest($token, $url, $authType = 'bearer', $username = null, &$httpCode = 0)
{
    // init curl
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60); // 60 second timeout for large requests

    // set headers
    if ($authType === 'legacy') {
        $headers = array("Authorization: $username:$token");
    } else {
        $headers = array("Authorization: Bearer $token");
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);

    // Check for curl errors
    if (curl_error($ch)) {
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        error_log("ERROR: cURL failed: $error (HTTP $httpCode) for URL: $url");
        return false;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // read response
    $jsonResponse = json_decode($response, true);

    // Check if JSON decoding was successful
    if ($jsonResponse === null && json_last_error() !== JSON_ERROR_NONE) {
        error_log("ERROR: Failed to decode JSON: " . json_last_error_msg());
        error_log("Response: " . $response);
        return false;
    }

    // return response
    return $jsonResponse;
}

// function get auth JWT from middleware
// $httpCode is filled with the HTTP status code of the login request
// (stays 0 if the request fails at network level)
function getJWTToken($cloudUsername, $cloudPassword, $cloudDomain, &$httpCode = 0)
{
    $loginPayload = json_encode([
        'username' => $cloudUsername,
        'password' => $cloudPassword
    ]);

    $loginUrl = "https://$cloudDomain/api/login";
    $ch = curl_init($loginUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $loginPayload);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Accept: application/json'
    ]);

    $response = curl_exec($ch);
    if ($response === false) {
        error_log("ERROR: cURL error during JWT authentication to {$loginUrl}: " . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200) {
        debug("JWT authentication failed on {$loginUrl} for {$cloudUsername}@{$cloudDomain}. HTTP code {$httpCode}", $cloudDomain);
        return false;
    }

    $jsonResponse = json_decode($response, true);
    if ($jsonResponse === null && json_last_error() !== JSON_ERROR_NONE) {
        error_log("ERROR: Failed to decode JWT login response from {$loginUrl}: " . json_last_error_msg());
        return false;
    }

    if (!isset($jsonResponse['token']) || !is_string($jsonResponse['token']) || $jsonResponse['token'] === '') {
        error_log("ERROR: Missing JWT token in response from {$loginUrl} for {$cloudUsername}@{$cloudDomain}");
        return false;
    }

    debug("JWT token generated for {$cloudUsername}@{$cloudDomain} using {$loginUrl}", $cloudDomain);
    return $jsonResponse['token'];
}

// function get legacy auth token from cti-server
function getLegacyAuthToken($cloudUsername, $cloudPassword, $cloudDomain)
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
    if ($response === false) {
        error_log("ERROR: cURL error during legacy authentication: " . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode !== 401) {
        debug("Legacy authentication failed for {$cloudUsername}@{$cloudDomain}. Expected HTTP 401, got {$httpCode}", $cloudDomain);
        return false;
    }

    // extract the nonce from the response header
    preg_match('/uthenticate: Digest ([0-9a-f]+)/', $response, $matches);
    if (!isset($matches[1])) {
        error_log("ERROR: Legacy authentication failed for {$cloudUsername}@{$cloudDomain}. No nonce found");
        return false;
    }

    $nonce = $matches[1];
    $tohash = "$cloudUsername:$cloudPassword:$nonce";
    $token = hash_hmac('sha1', $tohash, $cloudPassword);

    debug("Legacy token generated for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
    return $token;
}

function isValidUserMeResponse($response)
{
    return is_array($response) && isset($response['endpoints']) && isset($response['endpoints']['extension']);
}

function isRecordingAllowed($userMe)
{
    return isset($userMe['profile']['macro_permissions']['settings']['value'])
        && $userMe['profile']['macro_permissions']['settings']['value'] === true
        && isset($userMe['profile']['macro_permissions']['settings']['permissions']['recording']['value'])
        && $userMe['profile']['macro_permissions']['settings']['permissions']['recording']['value'] === true;
}

function buildApiUrl($cloudDomain, $basePath, $endpointPath)
{
    return "https://$cloudDomain{$basePath}{$endpointPath}";
}

// Build auth context with automatic fallback:
// 1) middleware mode: /api + Authorization: Bearer <jwt>
// 2) legacy mode: /webrest + Authorization: username:token
// $authRejected is set to true only when the upstream explicitly rejected
// the credentials (HTTP 401/403), as opposed to other failures (network
// errors, middleware not installed, invalid responses)
function getAuthContext($cloudUsername, $cloudPassword, $cloudDomain, $isToken = false, &$authRejected = false)
{
    $authRejected = false;
    if (!$isToken) {
        // try middleware first
        $jwtHttpCode = 0;
        $jwtToken = getJWTToken($cloudUsername, $cloudPassword, $cloudDomain, $jwtHttpCode);
        if ($jwtToken) {
            $userMe = makeRequest($jwtToken, buildApiUrl($cloudDomain, '/api', '/user/me'), 'bearer');
            if (isValidUserMeResponse($userMe)) {
                debug("Using middleware mode for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
                return [
                    'basePath' => '/api',
                    'authType' => 'bearer',
                    'token' => $jwtToken,
                    'userMe' => $userMe
                ];
            }
        }

        // The middleware rejected the credentials: it has already performed
        // the LDAP bind against the user provider (AD/LDAP), so retrying on
        // the legacy endpoint would repeat the same failed bind and increment
        // the AD bad password count, eventually locking the account.
        // Fall back to legacy only when the middleware is missing (404) or
        // unreachable (network error / 5xx).
        if ($jwtHttpCode === 401 || $jwtHttpCode === 403) {
            debug("Middleware rejected credentials for {$cloudUsername}@{$cloudDomain} (HTTP {$jwtHttpCode}), skipping legacy fallback", $cloudDomain);
            $authRejected = true;
            return false;
        }

        // fallback to legacy
        $legacyToken = getLegacyAuthToken($cloudUsername, $cloudPassword, $cloudDomain);
        if ($legacyToken) {
            $userMe = makeRequest($legacyToken, buildApiUrl($cloudDomain, '/webrest', '/user/me'), 'legacy', $cloudUsername);
            if (isValidUserMeResponse($userMe)) {
                debug("Using legacy mode for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
                return [
                    'basePath' => '/webrest',
                    'authType' => 'legacy',
                    'token' => $legacyToken,
                    'userMe' => $userMe
                ];
            }
        }
    } else {
        // qrcode/token-based login: try token as JWT first
        $bearerHttpCode = 0;
        $userMe = makeRequest($cloudPassword, buildApiUrl($cloudDomain, '/api', '/user/me'), 'bearer', null, $bearerHttpCode);
        if (isValidUserMeResponse($userMe)) {
            debug("Using middleware token mode for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
            return [
                'basePath' => '/api',
                'authType' => 'bearer',
                'token' => $cloudPassword,
                'userMe' => $userMe
            ];
        }

        // fallback: token is legacy hash
        $legacyHttpCode = 0;
        $userMe = makeRequest($cloudPassword, buildApiUrl($cloudDomain, '/webrest', '/user/me'), 'legacy', $cloudUsername, $legacyHttpCode);
        if (isValidUserMeResponse($userMe)) {
            debug("Using legacy token mode for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
            return [
                'basePath' => '/webrest',
                'authType' => 'legacy',
                'token' => $cloudPassword,
                'userMe' => $userMe
            ];
        }

        // The token has been explicitly rejected on both endpoints: it has
        // been revoked or regenerated server side (e.g. a new QR code was
        // created). Other combinations (network error, middleware missing)
        // are not treated as a rejection.
        if (($bearerHttpCode === 401 || $bearerHttpCode === 403) &&
            ($legacyHttpCode === 401 || $legacyHttpCode === 403)) {
            debug("Token rejected on both endpoints for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
            $authRejected = true;
        }
    }

    return false;
}

// login to cti using the cloud credentials and get the sip credentials using the /user/me API
// $authRejected is set to true when the failure is an explicit credential
// rejection (see getAuthContext)
function getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken = false, &$authRejected = false)
{
    $authContext = getAuthContext($cloudUsername, $cloudPassword, $cloudDomain, $isToken, $authRejected);
    if (!$authContext) {
        if ($authRejected) {
            error_log("ERROR: Credentials rejected by upstream for {$cloudUsername}@{$cloudDomain}");
        } else {
            error_log("ERROR: Authentication failed for {$cloudUsername}@{$cloudDomain} in both middleware and legacy modes");
        }
        return false;
    }

    // user/me response was already validated while building auth context
    $response = $authContext['userMe'];

    // Step 3: check if lk is set and is valid
    if (isset($response['lkhash'])) {
        // read api url from env
        $url = getenv("VALIDATE_LK_URL");

        // create curl state
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        // do not print the answer into the provisioning XML
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // bounded wait: on timeout httpCode is 0 and the provisioning is refused
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        // set headers
        $headers = array("Authorization: Bearer " . $response['lkhash']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        // exec curl
        $lkcheck = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // print debug
        debug("lkhash validated for {$cloudUsername}@{$cloudDomain}", $cloudDomain);

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
                'proxy_fqdn' => (isset($response['proxy_fqdn']) ? $response['proxy_fqdn'] : ""),
                'authContext' => $authContext
            ];
        }
    }

    // if step 4 has no endpoints, return false
    debug("No endpoints found for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
    return false;
}

// NethVoice chat: add the app messaging services when the tenant has the chat gateway
function chatAccountXml($cloudDomain)
{
    $base = "https://$cloudDomain/chat-gw";
    $ch = curl_init("$base/healthz");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    // the gateway's own answer, not a page that says 200 to any path
    if ($code != 200 || trim((string) $body) !== "ok") {
        return "";
    }
    $fetch = '{"username":"%account[cloud_username]%","password":"%account[cloud_password]%","last_id":"%last_known_sms_id%","last_sent_id":"%last_known_sent_sms_id%","device":"%installid%"}';
    $send = '{"from":"%account[cloud_username]%","password":"%account[cloud_password]%","to":"%sms_to%","body":"%sms_body%","content_type":"%content_type%"}';
    $push = '{"username":"%account[cloud_username]%","password":"%account[cloud_password]%","token_calls":"%pushTokenIncomingCall%","token_msgs":"%pushTokenOther%","selector":"%selector%","appId_calls":"%pushappid_incoming_call%","appId_msgs":"%pushappid_other%"}';
    return "<genericSmsFetchUrl>$base/api/client/fetch_messages</genericSmsFetchUrl>\n" .
        "<genericSmsFetchPostData>$fetch</genericSmsFetchPostData>\n" .
        "<genericSmsFetchContentType>application/json</genericSmsFetchContentType>\n" .
        "<genericSmsSendUrl>$base/api/client/send_message</genericSmsSendUrl>\n" .
        "<genericSmsSendPostData>$send</genericSmsSendPostData>\n" .
        "<genericSmsSendContentType>application/json</genericSmsSendContentType>\n" .
        "<pushTokenReporterUrl>$base/api/client/push_token_report</pushTokenReporterUrl>\n" .
        "<pushTokenReporterPostData>$push</pushTokenReporterPostData>\n" .
        "<pushTokenReporterContentType>application/json</pushTokenReporterContentType>\n" .
        // Deleting a message: for me only, or for everyone when it is mine.
        "<msgLocalDeleteSupported>1</msgLocalDeleteSupported>\n" .
        "<msgRemoteDeleteSupported>1</msgRemoteDeleteSupported>\n";
}

// NethVoice operators (users with a main extension) keyed by username
function getOperators($authContext, $cloudDomain, $cloudUsername)
{
    $url = buildApiUrl($cloudDomain, $authContext['basePath'], '/user/endpoints/all');
    $response = makeRequest($authContext['token'], $url, $authContext['authType'], $cloudUsername);
    if (!is_array($response)) {
        debug("Failed to get operators for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
        return [];
    }

    $operators = [];
    foreach ($response as $username => $user) {
        if (!is_string($username) || !is_array($user) || empty($user['endpoints']['mainextension'][0]['id'])) {
            continue;
        }
        $operators[$username] = $user;
    }
    return $operators;
}

// Acrobits only takes a URL for contact avatars and quick dial portraits, so
// the operators' pictures are kept in a local cache and served by this proxy
// through signed URLs (see serveAvatar).
const AVATAR_EXT = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'image/webp' => 'webp'
];

// the pictures are downloaded again at most once an hour per tenant
const AVATAR_CACHE_TTL = 3600;

// all_avatars is one JSON with every picture, tens of MB for a big tenant: it
// is streamed to a temporary file and read back one picture at a time, so the
// memory needed does not grow with the tenant. The size limit only guards the disk.
const AVATAR_DOWNLOAD_MAX = 256 * 1024 * 1024;

// GET /user/all_avatars into a temporary file; its path, or null when it cannot be used
function fetchAllAvatars($authContext, $cloudDomain, $cloudUsername)
{
    // a download left behind by a request that died halfway
    foreach (glob(sys_get_temp_dir() . '/all_avatars*') ?: [] as $stale) {
        if (filemtime($stale) < time() - 600) {
            @unlink($stale);
        }
    }
    $file = tempnam(sys_get_temp_dir(), 'all_avatars');
    $out = $file === false ? false : fopen($file, 'wb');
    if ($out === false) {
        error_log("ERROR: Failed to create a temporary file for the avatars of $cloudDomain");
        return null;
    }

    $ch = curl_init(buildApiUrl($cloudDomain, $authContext['basePath'], '/user/all_avatars'));
    curl_setopt($ch, CURLOPT_FILE, $out);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 120);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        $authContext['authType'] === 'legacy'
            ? "Authorization: $cloudUsername:{$authContext['token']}"
            : "Authorization: Bearer {$authContext['token']}"
    ]);
    // give up as soon as the body grows past the limit, with or without Content-Length
    curl_setopt($ch, CURLOPT_MAXFILESIZE_LARGE, AVATAR_DOWNLOAD_MAX);
    curl_setopt($ch, CURLOPT_NOPROGRESS, false);
    curl_setopt($ch, CURLOPT_XFERINFOFUNCTION, function ($ch, $downloadTotal, $downloaded) {
        return $downloaded > AVATAR_DOWNLOAD_MAX ? 1 : 0;
    });
    $ok = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    fclose($out);

    if ($ok === false || $code !== 200) {
        debug("Avatars not downloaded for {$cloudDomain} (HTTP $code" . ($error !== '' ? ", $error" : '') . ")", $cloudDomain);
        @unlink($file);
        return null;
    }
    return $file;
}

// call $fn($username, $dataUri) for each picture in a downloaded all_avatars
// file, reading it by chunks: the JSON is a flat object of strings (a user
// without a picture has null, which is skipped)
function eachAvatar($file, $fn, $chunk = 1048576)
{
    $in = fopen($file, 'rb');
    if ($in === false) {
        return;
    }
    $carry = '';
    while (!feof($in)) {
        $buf = $carry . fread($in, $chunk);
        if (preg_match_all('/"((?:[^"\\\\]|\\\\.)++)"\s*:\s*"((?:[^"\\\\]|\\\\.)*+)"/', $buf, $pairs, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($pairs as $pair) {
                // the JSON string tokens, escapes included: decoded as such
                $username = json_decode('"' . $pair[1][0] . '"');
                $dataUri = json_decode('"' . $pair[2][0] . '"');
                if (is_string($username) && is_string($dataUri)) {
                    $fn($username, $dataUri);
                }
            }
            $last = end($pairs);
            // what follows the last complete pair may be the start of the next one
            $carry = substr($buf, $last[0][1] + strlen($last[0][0]));
        } else {
            $carry = $buf;
        }
    }
    fclose($in);
}

// cache directory for a tenant, false when the domain is not a safe path component
function avatarCacheDir($cloudDomain)
{
    if (!preg_match('/^[a-z0-9.-]+$/', $cloudDomain) || strpos($cloudDomain, '..') !== false) {
        return false;
    }
    return '/tmp/avatars/' . $cloudDomain;
}

// username => ['sha1' => ..., 'mime' => ...] of the cached avatars
function readAvatarIndex($cloudDomain)
{
    $dir = avatarCacheDir($cloudDomain);
    if ($dir === false || !is_file("$dir/index.json")) {
        return [];
    }
    $index = json_decode((string) file_get_contents("$dir/index.json"), true);
    return is_array($index) ? $index : [];
}

// whether the avatar cache is in place (the contacts are regenerated when it is
// not, e.g. after a container restart, so that the avatar URLs work again)
function avatarsCached($cloudDomain)
{
    $dir = avatarCacheDir($cloudDomain);
    return $dir === false || is_file("$dir/index.json");
}

// cache keys: a username for an operator, "~" plus the room for a chat group
const GROUP_AVATAR_PREFIX = '~';

function isAvatarKey($key)
{
    return is_string($key) && preg_match('/^[A-Za-z0-9._@~-]+$/', $key) && strpos($key, '..') === false;
}

// store one picture given as a data URI; returns its index entry, null when it is not usable
function storeAvatar($dir, $key, $dataUri)
{
    if (!is_string($dataUri) || !preg_match('#^data:(image/(?:jpeg|png|gif|webp));base64,(.+)$#s', $dataUri, $m)) {
        return null;
    }
    $image = base64_decode($m[2], true);
    if ($image === false || $image === '') {
        return null;
    }

    $sha1 = sha1($image);
    $file = "$dir/$key";
    // write the file only when the picture changed, atomically
    if (!is_file($file) || sha1_file($file) !== $sha1) {
        $tmp = "$file.tmp" . getmypid();
        if (file_put_contents($tmp, $image) === false || !rename($tmp, $file)) {
            @unlink($tmp);
            return null;
        }
    }
    return ['sha1' => $sha1, 'mime' => $m[1]];
}

// atomic rewrite of the index; the caller holds the cache lock
function writeAvatarIndex($dir, $index)
{
    $tmp = "$dir/index.json.tmp" . getmypid();
    if (file_put_contents($tmp, json_encode($index)) === false || !rename($tmp, "$dir/index.json")) {
        @unlink($tmp);
        error_log("ERROR: Failed to write avatar index in $dir");
    }
}

// the cache directory and its lock, false when the cache is not usable
function openAvatarCache($cloudDomain)
{
    $dir = avatarCacheDir($cloudDomain);
    if ($dir === false) {
        return false;
    }
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        error_log("ERROR: Failed to create avatar cache $dir");
        return false;
    }
    $lock = fopen("$dir/.lock", 'c');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        error_log("ERROR: Failed to lock avatar cache $dir");
        return false;
    }
    return [$dir, $lock];
}

function closeAvatarCache($lock)
{
    flock($lock, LOCK_UN);
    fclose($lock);
}

// download the operators' avatars into the local cache, return the index;
// a cache younger than $maxAge seconds is reused as it is
function syncAvatars($authContext, $cloudDomain, $cloudUsername, $maxAge = 0)
{
    $dir = avatarCacheDir($cloudDomain);
    if ($dir === false) {
        return [];
    }
    if ($maxAge > 0 && is_file("$dir/index.json") && filemtime("$dir/index.json") > time() - $maxAge) {
        return readAvatarIndex($cloudDomain);
    }

    $download = fetchAllAvatars($authContext, $cloudDomain, $cloudUsername);
    if ($download === null) {
        debug("Failed to get avatars for {$cloudUsername}@{$cloudDomain}, keeping the cached ones", $cloudDomain);
        return readAvatarIndex($cloudDomain);
    }

    $cache = openAvatarCache($cloudDomain);
    if ($cache === false) {
        @unlink($download);
        return [];
    }
    list($dir, $lock) = $cache;

    // the groups' pictures are kept: they are refreshed by cacheGroupAvatars
    $index = [];
    foreach (readAvatarIndex($cloudDomain) as $key => $entry) {
        if (strpos($key, GROUP_AVATAR_PREFIX) === 0) {
            $index[$key] = $entry;
        }
    }
    eachAvatar($download, function ($username, $dataUri) use ($dir, &$index) {
        if (!isAvatarKey($username) || strpos($username, GROUP_AVATAR_PREFIX) === 0) {
            return;
        }
        $entry = storeAvatar($dir, $username, $dataUri);
        if ($entry !== null) {
            $index[$username] = $entry;
        }
    });
    @unlink($download);

    // drop the pictures of users that no longer have one (not the cache's own
    // files, nor the temporary files of a sync running in another request)
    foreach (scandir($dir) ?: [] as $entry) {
        if (in_array($entry, ['.', '..', '.lock', 'regen'], true) || substr($entry, -5) === '.json' || preg_match('/\.tmp\d+$/', $entry)) {
            continue;
        }
        if (!isset($index[$entry])) {
            @unlink("$dir/$entry");
        }
    }

    writeAvatarIndex($dir, $index);
    closeAvatarCache($lock);

    debug("Avatars cached for {$cloudDomain}: " . count($index), $cloudDomain);
    return $index;
}

// username => main extension of the operators, kept per tenant for an hour so
// that the quick dial does not ask the users list on every call; the contacts
// pass the operators it just downloaded to refresh it
function operatorExtensions($authContext, $cloudDomain, $cloudUsername, $operators = null)
{
    $dir = avatarCacheDir($cloudDomain);
    $file = $dir === false ? null : "$dir/extensions.json";
    if ($operators === null) {
        if ($file !== null && is_file($file) && filemtime($file) > time() - AVATAR_CACHE_TTL) {
            $cached = json_decode((string) file_get_contents($file), true);
            if (is_array($cached)) {
                return $cached;
            }
        }
        $operators = getOperators($authContext, $cloudDomain, $cloudUsername);
    }

    $extensions = [];
    foreach ($operators as $username => $user) {
        $extensions[$username] = (string) $user['endpoints']['mainextension'][0]['id'];
    }
    if ($file !== null && (is_dir($dir) || mkdir($dir, 0700, true) || is_dir($dir))) {
        $tmp = "$file.tmp" . getmypid();
        if (file_put_contents($tmp, json_encode($extensions)) === false || !rename($tmp, $file)) {
            @unlink($tmp);
        }
    }
    return $extensions;
}

// NethVoice chat groups of the user with their pictures, from the chat gateway
// (middleware mode only: the gateway takes the CTI token)
function getChatGroups($authContext, $cloudDomain, $cloudUsername)
{
    if ($authContext['authType'] !== 'bearer') {
        return [];
    }
    $ch = curl_init("https://$cloudDomain/chat-gw/groups");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_TIMEOUT, 25);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer {$authContext['token']}"]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    // no gateway, or one without this service yet: no groups
    if ($code != 200) {
        debug("No chat groups for {$cloudUsername}@{$cloudDomain} (HTTP $code)", $cloudDomain);
        return [];
    }
    $response = json_decode((string) $body, true);
    if (!isset($response['groups']) || !is_array($response['groups'])) {
        return [];
    }

    $groups = [];
    foreach ($response['groups'] as $group) {
        if (!is_array($group) || empty($group['room']) || !is_string($group['room']) || empty($group['name']) || !is_string($group['name'])) {
            continue;
        }
        $room = explode('@', $group['room'], 2)[0];
        if (!isAvatarKey($room)) {
            continue;
        }
        // the group's address in the app: the gateway's, else the name as the gateway shows it
        $address = (isset($group['address']) && is_string($group['address']) && $group['address'] !== '')
            ? $group['address']
            : str_replace([' ', ','], ["\u{00A0}", "\u{201A}"], $group['name']);
        $groups[] = [
            'room' => $room,
            'name' => $group['name'],
            'address' => $address,
            'avatar' => isset($group['avatar']) && is_string($group['avatar']) ? $group['avatar'] : ''
        ];
    }
    return $groups;
}

// store the groups' pictures in the cache, return the whole index
function cacheGroupAvatars($cloudDomain, $groups)
{
    $cache = openAvatarCache($cloudDomain);
    if ($cache === false) {
        return readAvatarIndex($cloudDomain);
    }
    list($dir, $lock) = $cache;

    $index = readAvatarIndex($cloudDomain);
    $changed = false;
    foreach ($groups as $group) {
        $key = GROUP_AVATAR_PREFIX . $group['room'];
        if ($group['avatar'] === '') {
            if (isset($index[$key])) {
                unset($index[$key]);
                @unlink("$dir/$key");
                $changed = true;
            }
            continue;
        }
        $entry = storeAvatar($dir, $key, $group['avatar']);
        if ($entry !== null && ($index[$key] ?? null) !== $entry) {
            $index[$key] = $entry;
            $changed = true;
        }
    }
    if ($changed) {
        writeAvatarIndex($dir, $index);
    }
    closeAvatarCache($lock);
    return $index;
}

// one contact per chat group with a picture: the app shows a group under its
// address, so a contact with that address gives it the picture
function groupContacts($groups, $avatars, $cloudDomain)
{
    $contacts = [];
    foreach ($groups as $group) {
        $key = GROUP_AVATAR_PREFIX . $group['room'];
        if (!isset($avatars[$key])) {
            continue;
        }
        $contacts[] = [
            'contactId' => "group-{$group['room']}",
            'displayName' => $group['name'],
            'fname' => $group['name'],
            'lname' => '',
            'company' => '',
            'notes' => '',
            'contactEntries' => [[
                'entryId' => '0',
                'label' => 'chat',
                'type' => 'tel',
                'uri' => $group['address']
            ]],
            'contactAddresses' => [],
            'avatar' => avatarUrl($cloudDomain, $key, $avatars[$key])
        ];
    }
    return $contacts;
}

function avatarSignature($cloudDomain, $username, $version)
{
    return substr(hash_hmac('sha256', "$cloudDomain/$username/$version", (string) getenv('TOKEN')), 0, 32);
}

// public base URL of this proxy, as seen by the app
function avatarBaseUrl()
{
    $host = getenv('APP_HOSTNAME');
    if ($host) {
        return "https://$host";
    }
    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
    return $proto . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
}

// signed URL of a cached avatar; the version makes the URL change with the picture
function avatarUrl($cloudDomain, $username, $entry)
{
    $version = substr($entry['sha1'], 0, 16);
    $signature = avatarSignature($cloudDomain, $username, $version);
    $ext = AVATAR_EXT[$entry['mime']];
    return avatarBaseUrl() . "/index.php/avatar/$cloudDomain/$username/$version/$signature.$ext";
}

// GET /index.php/avatar/<domain>/<username>/<version>/<signature>.<ext>
function serveAvatar($path)
{
    if (!preg_match('#^/index\.php/avatar/([a-z0-9.-]+)/([A-Za-z0-9._@~-]+)/([0-9a-f]{16})/([0-9a-f]{32})\.(jpg|png|gif|webp)$#', $path, $m)) {
        header('HTTP/1.1 404 Not Found');
        return;
    }
    list(, $cloudDomain, $username, $version, $signature) = $m;

    if (!hash_equals(avatarSignature($cloudDomain, $username, $version), $signature)) {
        debug("Invalid avatar signature for {$username}@{$cloudDomain}", $cloudDomain);
        header('HTTP/1.1 404 Not Found');
        return;
    }

    // serve the current picture, even when the app still holds an older URL
    $dir = avatarCacheDir($cloudDomain);
    $index = readAvatarIndex($cloudDomain);
    if ($dir === false || !isset($index[$username]['mime']) || strpos($username, '..') !== false || !is_file("$dir/$username")) {
        header('HTTP/1.1 404 Not Found');
        return;
    }

    header('HTTP/1.1 200 OK');
    header('Content-Type: ' . $index[$username]['mime']);
    header('Content-Length: ' . filesize("$dir/$username"));
    header('Cache-Control: private, max-age=86400');
    header('ETag: "' . $index[$username]['sha1'] . '"');
    readfile("$dir/$username");
}

// one contact per operator: main extension (matches the BLF list, so the app
// shows the presence), mobile numbers, emails and the avatar
function operatorContacts($operators, $avatars, $cloudDomain)
{
    $contacts = [];
    foreach ($operators as $username => $user) {
        $displayName = trim($user['name'] ?? '');
        if ($displayName === '') {
            $displayName = $username;
        }
        $firstName = trim($user['firstname'] ?? '');
        $lastName = trim($user['lastname'] ?? '');
        if ($firstName === '' && $lastName === '') {
            $parts = explode(' ', $displayName, 2);
            $firstName = $parts[0];
            $lastName = $parts[1] ?? '';
        }

        $entries = [[
            'label' => 'extension',
            'type' => 'tel',
            'uri' => $user['endpoints']['mainextension'][0]['id']
        ]];
        foreach ($user['endpoints']['cellphone'] ?? [] as $cellphone) {
            if (!empty($cellphone['id'])) {
                $entries[] = ['label' => 'mobile', 'type' => 'tel', 'uri' => $cellphone['id']];
            }
        }
        foreach ($user['endpoints']['email'] ?? [] as $email) {
            if (!empty($email['id'])) {
                $entries[] = ['label' => 'work email', 'type' => 'email', 'uri' => $email['id']];
            }
        }
        foreach ($entries as $i => $entry) {
            $entries[$i] = ['entryId' => (string) $i] + $entry;
        }

        $contact = [
            'contactId' => "user-$username",
            'displayName' => $displayName,
            'fname' => $firstName,
            'lname' => $lastName,
            'company' => '',
            'notes' => '',
            'contactEntries' => $entries,
            'contactAddresses' => []
        ];
        if (isset($avatars[$username])) {
            $contact['avatar'] = avatarUrl($cloudDomain, $username, $avatars[$username]);
        }
        $contacts[] = $contact;
    }
    return $contacts;
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
        debug("Using qrcode login for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
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
            $authRejected = false;
            $result = getSipCredentials($cloudUsername, $cloudPassword, $cloudDomain, $isToken, $authRejected);

            // check if sip credentials exists
            if (!$result) {
                // Credentials explicitly rejected upstream (e.g. password
                // changed on AD/LDAP or QR token revoked): answer with the
                // extProvLogoutStatusCode so the app logs the user out and
                // asks for new credentials instead of retrying forever.
                if ($authRejected) {
                    error_log("ERROR: Credentials rejected for {$cloudUsername}@{$cloudDomain}, asking the app to log out");
                    return header("HTTP/1.1 410 Gone");
                }
                error_log("ERROR: Failed to get sip credentials for {$cloudUsername}@{$cloudDomain}");
                return header("HTTP/1.0 404 Not Found");
            }

            $authContext = isset($result['authContext']) ? $result['authContext'] : getAuthContext($cloudUsername, $cloudPassword, $cloudDomain, $isToken);
            if (!$authContext) {
                error_log("ERROR: Failed to get auth context for {$cloudUsername}@{$cloudDomain}");
                return header("HTTP/1.0 404 Not Found");
            }

            // get busy lamp extensions
            $url = buildApiUrl($cloudDomain, $authContext['basePath'], '/user/endpoints/all');

            // make request
            $response = makeRequest($authContext['token'], $url, $authContext['authType'], $cloudUsername);

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
                debug("No proxy fqdn found in response for {$cloudUsername}@{$cloudDomain}", $cloudDomain);
            }

            // compose final xml string
            $xmlConfString = "
                    <account>
                    <cloud_username>{$cloudUsername}@{$cloudDomain}{$loginTypeString}</cloud_username>
                    <cloud_password>{$cloudPassword}</cloud_password>
                    <username>{$result['sipUser']}</username>
                    <password>{$result['sipPassword']}</password>
                    <extProvInterval>3600</extProvInterval>
                    <extProvLogoutStatusCode>410</extProvLogoutStatusCode>
                    $proxy
                    <host>{$cloudDomain}</host>
                    <transport>tls+sip:</transport>
                    <blf>" . implode("", $busylamps) . "</blf>
                    </account>
                    ";

            $xmlConfString = str_replace('</account>', chatAccountXml($cloudDomain) . '</account>', $xmlConfString);

            // return xml string
            echo $xmlConfString;

            // print debug
            debug('Returning sip credentials: ' . preg_replace('/password>.*<\//', 'password>xxxx</', $xmlConfString), $cloudDomain);

            break;
        // handle Contact Sources app
        case 'contacts':
            $authContext = getAuthContext($cloudUsername, $cloudPassword, $cloudDomain, $isToken);
            if (!$authContext) {
                debug("ERROR: Failed to build auth context for contacts {$cloudUsername}", $cloudDomain);
                header("HTTP/1.0 404 Not Found");
                return;
            }

            // get phonebook counters
            $url = buildApiUrl($cloudDomain, $authContext['basePath'], '/phonebook/search/?offset=0&limit=1&view=all');

            // make request
            $response = makeRequest($authContext['token'], $url, $authContext['authType'], $cloudUsername);

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

            // Debug all received headers
            debug("All received headers: " . json_encode($headers), $cloudDomain);

            // Try multiple ways to get If-Modified-Since
            $ifModifiedSince = null;
            if (isset($headers['If-Modified-Since'])) {
                $ifModifiedSince = $headers['If-Modified-Since'];
            } elseif (isset($_SERVER['HTTP_IF_MODIFIED_SINCE'])) {
                $ifModifiedSince = $_SERVER['HTTP_IF_MODIFIED_SINCE'];
            }

            // Debug If-Modified-Since header
            if ($ifModifiedSince) {
                debug("Received If-Modified-Since: " . $ifModifiedSince, $cloudDomain);
            } else {
                debug("No If-Modified-Since header found (tried apache_request_headers and \$_SERVER)", $cloudDomain);
            }

            // check if counter is equal or last modified is 24 hours ago, return 304 Not Modified;
            // a copy older than this file is regenerated too, so that a deploy
            // changing the contacts format reaches every device at its next poll;
            // touching <avatar cache>/regen does the same for one tenant
            $freshSince = max(strtotime('-24 hours', time()), filemtime(__FILE__));
            $regenMarker = avatarCacheDir($cloudDomain);
            if ($regenMarker !== false && is_file("$regenMarker/regen")) {
                $freshSince = max($freshSince, filemtime("$regenMarker/regen"));
            }
            if ($ifModifiedSince && strtotime($ifModifiedSince) >= $freshSince && $count == $response['count'] && avatarsCached($cloudDomain)) {
                // print debug
                debug('Phonebook contacts are the same: ' . $count . ' since ' . $ifModifiedSince, $cloudDomain);

                // return header 304
                header('HTTP/1.1 304 Not Modified');
                return;
            }

            // new contacts found, write to debug log
            debug('Phonebook new contacts found: ' . $response['count'], $cloudDomain);

            // operators come first, once each, from the users list; then the
            // user's chat groups that have a picture
            $operators = getOperators($authContext, $cloudDomain, $cloudUsername);
            operatorExtensions($authContext, $cloudDomain, $cloudUsername, $operators);
            syncAvatars($authContext, $cloudDomain, $cloudUsername, AVATAR_CACHE_TTL);
            $groups = getChatGroups($authContext, $cloudDomain, $cloudUsername);
            $avatars = cacheGroupAvatars($cloudDomain, $groups);
            $contacts = array_merge(operatorContacts($operators, $avatars, $cloudDomain), groupContacts($groups, $avatars, $cloudDomain));
            debug("Operators and groups added as contacts: " . count($contacts) . " (" . count($groups) . " groups, " . count($avatars) . " avatars cached)", $cloudDomain);

            // get all contacts using chunked requests for better performance
            $skippedExtensions = 0;
            $totalContacts = $response['count'];
            $chunkSize = 8000; // Large chunks to minimize API calls
            $offset = 0;
            $chunkNumber = 1;
            $totalChunks = ceil($totalContacts / $chunkSize);

            debug("Starting chunked processing: $totalContacts contacts in $totalChunks chunks of $chunkSize", $cloudDomain);
            $overallStart = microtime(true);

            while ($offset < $totalContacts) {
                $url = buildApiUrl($cloudDomain, $authContext['basePath'], "/phonebook/search/?view=all&limit=$chunkSize&offset=$offset");

                debug("Processing chunk $chunkNumber/$totalChunks (offset $offset)", $cloudDomain);

                // Retry logic for failed chunks
                $chunkResponse = false;
                $retries = 0;
                $maxRetries = 2;

                while ($retries <= $maxRetries && ($chunkResponse === false || !isset($chunkResponse['rows']))) {
                    if ($retries > 0) {
                        debug("Retrying chunk $chunkNumber (attempt " . ($retries + 1) . "/" . ($maxRetries + 1) . ")", $cloudDomain);
                        sleep(1); // Wait 1 second before retry
                    }

                    $chunkResponse = makeRequest($authContext['token'], $url, $authContext['authType'], $cloudUsername);
                    $retries++;
                }

                if ($chunkResponse === false || !isset($chunkResponse['rows'])) {
                    debug("ERROR: Failed to get phonebook chunk at offset $offset after $maxRetries retries for {$cloudUsername}", $cloudDomain);
                    break;
                }

                $chunkCount = count($chunkResponse['rows']);

                foreach ($chunkResponse['rows'] as $contact) {
                // "extension" rows are the NethVoice users synced into the
                // centralized phonebook (stale copies may pile up there):
                // operators are already listed once from the users list
                if (($contact['type'] ?? '') === 'extension') {
                    $skippedExtensions++;
                    continue;
                }

                // compose contacts object with minimal memory footprint
                $firstName = trim($contact["name"] ?? '');
                if ($firstName === '-') {
                    $firstName = '';
                }
                $displayName = trim($firstName . ' ' . ($contact["surname"] ?? ''));
                if (empty($displayName)) {
                    $displayName = $contact["company"] ?? "Unknown Contact";
                }

                $contacts[] = [
                    "contactId" => $contact["id"] ?? uniqid(),
                    "displayName" => $displayName,
                    "fname" => $firstName,
                    "lname" => $contact["surname"] ?? "",
                    "company" => $contact["company"] ?? "",
                    "notes" => $contact["notes"] ?? "",
                    "contactEntries" => array_values(array_filter([
                        !empty($contact["homephone"]) ? [
                            "entryId" => "0",
                            "label" => "home phone",
                            "type" => "tel",
                            "uri" => $contact["homephone"]
                        ] : null,
                        !empty($contact["workphone"]) ? [
                            "entryId" => "1",
                            "label" => "work phone",
                            "type" => "tel",
                            "uri" => $contact["workphone"]
                        ] : null,
                        !empty($contact["cellphone"]) ? [
                            "entryId" => "2",
                            "label" => "mobile",
                            "type" => "tel",
                            "uri" => $contact["cellphone"]
                        ] : null,
                        !empty($contact["homeemail"]) ? [
                            "entryId" => "3",
                            "label" => "home email",
                            "type" => "email",
                            "uri" => $contact["homeemail"]
                        ] : null,
                        !empty($contact["workemail"]) ? [
                            "entryId" => "4",
                            "label" => "work email",
                            "type" => "email",
                            "uri" => $contact["workemail"]
                        ] : null
                    ])),
                    "contactAddresses" => array_values(array_filter([
                        (!empty($contact["homestreet"]) || !empty($contact["homecity"]) || !empty($contact["homeprovince"]) || !empty($contact["homepostalcode"]) || !empty($contact["homecountry"])) ? [
                            "addressId" => "0",
                            "label" => "home address",
                            "city" => $contact["homecity"] ?? "",
                            "country" => $contact["homecountry"] ?? "",
                            "countryCode" => "",
                            "state" => $contact["homeprovince"] ?? "",
                            "street" => $contact["homestreet"] ?? "",
                            "zip" => $contact["homepostalcode"] ?? ""
                        ] : null,
                        (!empty($contact["workstreet"]) || !empty($contact["workcity"]) || !empty($contact["workprovince"]) || !empty($contact["workpostalcode"]) || !empty($contact["workcountry"])) ? [
                            "addressId" => "1",
                            "label" => "work address",
                            "city" => $contact["workcity"] ?? "",
                            "country" => $contact["workcountry"] ?? "",
                            "countryCode" => "",
                            "state" => $contact["workprovince"] ?? "",
                            "street" => $contact["workstreet"] ?? "",
                            "zip" => $contact["workpostalcode"] ?? ""
                        ] : null
                    ]))
                ];
                }

                // Free memory from chunk response
                unset($chunkResponse);

                // Check memory and time limits with warnings
                $memoryUsage = round(memory_get_usage(true) / 1024 / 1024, 1);
                $totalElapsed = microtime(true) - $overallStart;

                if ($memoryUsage > 400) {
                    debug("WARNING: Memory usage too high ({$memoryUsage}MB), stopping at chunk $chunkNumber", $cloudDomain);
                    break;
                }

                if ($totalElapsed > 45) {
                    debug("WARNING: Processing taking too long ({$totalElapsed}s), stopping at chunk $chunkNumber", $cloudDomain);
                    break;
                }

                // move to next chunk
                $offset += $chunkSize;
                $chunkNumber++;
            }

            debug("Completed chunked processing: " . count($contacts) . "/$totalContacts contacts processed, $skippedExtensions extension rows skipped", $cloudDomain);

            // set counter in a file
            file_put_contents("/tmp/phonebook_counters_" . $cloudDomain, $response['count']);

            // set headers
            header("Content-type: application/json");
            header("Last-Modified: " . gmdate('D, d M Y H:i:s') . ' GMT');
            header('HTTP/1.1 200 OK');

            // print results
            $result = json_encode(array("contacts" => $contacts));

            // Check if JSON encoding succeeded
            if ($result === false) {
                debug("ERROR: JSON encoding failed: " . json_last_error_msg(), $cloudDomain);
                http_response_code(500);
                echo '{"error": "JSON encoding failed"}';
            } else {
                echo $result;
            }

            break;
        case 'quickdial':
            $authContext = getAuthContext($cloudUsername, $cloudPassword, $cloudDomain, $isToken);
            if (!$authContext) {
                debug("Failed to build auth context for quickdial {$cloudUsername}, returning fail-closed norec=1", $cloudDomain);
                header("Content-type: text/xml");
                header('HTTP/1.1 200 OK');
                echo '<root><modifications><prefKeys><norec>1</norec></prefKeys></modifications></root>';
                return;
            }

            $norec = isRecordingAllowed($authContext['userMe']) ? 0 : 1;
            debug("Call recording permission for {$cloudUsername}@{$cloudDomain}: norec={$norec}", $cloudDomain);

            // operators' avatars for the favorites, looked up by extension
            $avatars = syncAvatars($authContext, $cloudDomain, $cloudUsername, AVATAR_CACHE_TTL);
            $usernameByExtension = array_flip(operatorExtensions($authContext, $cloudDomain, $cloudUsername));

            // get quick dials
            $url = buildApiUrl($cloudDomain, $authContext['basePath'], '/phonebook/speeddials');

            // make request
            $response = makeRequest($authContext['token'], $url, $authContext['authType'], $cloudUsername);

            // create quickdials object
            $quickdials = array();

            // create favorite list
            $favorites = array();

            // loop quickdials api response
            if (is_array($response)) {
                foreach ($response as $quickdial) {
                    // check if type is speeddial-favorite
                    if ($quickdial['notes'] == 'speeddial-favorite') {
                        // favorites are operators: add the portrait when they have one
                        $portrait = '';
                        $username = $usernameByExtension[$quickdial['speeddial_num']] ?? ($quickdial['name'] ?? '');
                        if ($username !== '' && isset($avatars[$username])) {
                            $portrait = '<portraitUrl>' . avatarUrl($cloudDomain, $username, $avatars[$username]) . '</portraitUrl>';
                        }

                        // compose xml structure
                        $quickdials[] = '<item id="' . $quickdial['speeddial_num'] . '"><displayName>' . htmlspecialchars((string) $quickdial['company'], ENT_XML1) . '</displayName><uri>' . $quickdial['speeddial_num'] . '</uri>' . $portrait . '</item>';

                        // add favorite num to list, useful to check extensions to remove from list
                        $favorites[] = $quickdial['speeddial_num'];

                        // print debug message
                    }
                }
            }

            // get all extensions
            $url = buildApiUrl($cloudDomain, $authContext['basePath'], '/astproxy/extensions');

            // make request
            $response = makeRequest($authContext['token'], $url, $authContext['authType'], $cloudUsername);

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
                    }
                }
            }

            // set header
            header("Content-type: text/xml");
            header('HTTP/1.1 200 OK');

            // print results
            echo '<root><modifications><prefKeys><norec>' . $norec . '</norec></prefKeys></modifications><quickDial>' . implode("", $quickdials) . implode("", $removes) . '</quickDial></root>';

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

// Operators' avatars for the app: plain GET on a signed URL
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && strpos($_SERVER['REQUEST_URI'], '/index.php/avatar/') === 0) {
    serveAvatar(strtok($_SERVER['REQUEST_URI'], '?'));
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
