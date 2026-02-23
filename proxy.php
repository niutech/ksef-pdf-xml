<?php
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
header("Access-Control-Allow-Origin: $origin");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Cookie, Accept-Encoding");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header("Access-Control-Max-Age: 86400");
    http_response_code(204);
    exit();
}

$targetUrl = $_GET['url'] ?? null;
if (!$targetUrl || !filter_var($targetUrl, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    die("Proxy error: Invalid or missing 'url' parameter.");
}

$allowedDomains = ['qr.ksef.mf.gov.pl'];
$targetHost = parse_url($targetUrl, PHP_URL_HOST);
if (!in_array($targetHost, $allowedDomains)) { die("Domain not allowed."); }

$ch = curl_init($targetUrl);
$method = $_SERVER['REQUEST_METHOD'];
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
if ($method !== 'GET' && $method !== 'HEAD') {
    curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
}
$requestHeaders = [];
$skipHeaders = ['host', 'origin', 'referer', 'content-length', 'connection','accept-encoding'];
foreach (getallheaders() as $name => $value) {
	if (!in_array(strtolower($name), $skipHeaders))
	    $requestHeaders[] = "$name: $value";
}
curl_setopt($ch, CURLOPT_HTTPHEADER, $requestHeaders);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
curl_setopt($ch, CURLOPT_AUTOREFERER, true);
$response = curl_exec($ch);

if (curl_errno($ch)) {
    http_response_code(500);
    die("Proxy error: " . curl_error($ch));
}

$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$responseHeadersRaw = substr($response, 0, $headerSize);
$responseBody = substr($response, $headerSize);
curl_close($ch);

http_response_code($httpCode);

$headerLines = explode("\r\n", $responseHeadersRaw);
foreach ($headerLines as $line) {
    if (empty(trim($line)) || strpos($line, 'HTTP/') === 0 || preg_match('/^(access-control-|content-encoding|transfer-encoding|content-length)/i', $line))
        continue;
    if (stripos($line, 'set-cookie:') === 0) {
        $cleanCookie = preg_replace('/;\s*domain=[^;]+/i', '', $line);
        $cleanCookie = preg_replace('/;\s*samesite=[a-z]+/i', '', $cleanCookie);
        $cleanCookie = preg_replace('/;\s*secure/i', '', $cleanCookie);
        $cleanCookie = rtrim($cleanCookie, "; ") . '; SameSite=None; Secure';
        header($cleanCookie, false);
    } else {
        header($line, false);
    }
}

echo $responseBody;
