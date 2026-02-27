<?php

/**
 * Deepgram Live Transcription Starter - PHP
 *
 * Simple WebSocket proxy to Deepgram's Live Transcription API using Ratchet
 * and ReactPHP. Forwards all messages (JSON and binary) bidirectionally
 * between client and Deepgram.
 *
 * Key Features:
 * - WebSocket proxy: Client WS -> Backend (Ratchet) -> Deepgram wss://
 * - HTTP endpoints: /api/session (JWT auth), /api/metadata (project info)
 * - JWT session authentication via WebSocket subprotocol
 * - CORS enabled for frontend communication
 * - Single event loop for HTTP + WebSocket on port 8081
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   WS   /api/live-transcription   - WebSocket proxy to Deepgram STT (auth required)
 *
 * Usage: php server.php
 */

require __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Yosymfony\Toml\Toml;
use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use Ratchet\Http\HttpServerInterface;
use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\Http\Router;
use Ratchet\WebSocket\WsServer;
use React\EventLoop\Loop;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use Psr\Http\Message\RequestInterface;

// ============================================================================
// ENVIRONMENT LOADING
// ============================================================================

Dotenv::createImmutable(__DIR__)->safeLoad();

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/**
 * Server configuration - These can be overridden via environment variables
 */
$PORT = $_ENV['PORT'] ?? '8081';
$HOST = $_ENV['HOST'] ?? '0.0.0.0';

// ============================================================================
// API KEY LOADING - Load Deepgram API key from .env
// ============================================================================

/**
 * Loads the Deepgram API key from environment variables.
 * Exits with a helpful error message if not found.
 *
 * @return string The Deepgram API key
 */
function loadApiKey(): string
{
    $apiKey = $_ENV['DEEPGRAM_API_KEY'] ?? '';

    if (empty($apiKey)) {
        fwrite(STDERR, "\nERROR: Deepgram API key not found!\n\n");
        fwrite(STDERR, "Please set your API key using one of these methods:\n\n");
        fwrite(STDERR, "1. Create a .env file (recommended):\n");
        fwrite(STDERR, "   DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "2. Environment variable:\n");
        fwrite(STDERR, "   export DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "Get your API key at: https://console.deepgram.com\n\n");
        exit(1);
    }

    return $apiKey;
}

$apiKey = loadApiKey();

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * In production, set SESSION_SECRET in .env for consistent token validation.
 */
$SESSION_SECRET = $_ENV['SESSION_SECRET'] ?? bin2hex(random_bytes(32));

/** JWT expiry time (1 hour) */
$JWT_EXPIRY = 3600;

/**
 * Creates a signed JWT session token.
 *
 * @return string Signed JWT token
 */
function createSessionToken(): string
{
    global $SESSION_SECRET, $JWT_EXPIRY;

    $now = time();
    $payload = [
        'iat' => $now,
        'exp' => $now + $JWT_EXPIRY,
    ];

    return JWT::encode($payload, $SESSION_SECRET, 'HS256');
}

/**
 * Validates JWT from WebSocket subprotocol: access_token.<jwt>
 * Returns the full protocol string if valid, null if invalid.
 *
 * @param string|null $protocols The Sec-WebSocket-Protocol header value
 * @return string|null The matched protocol string or null
 */
function validateWsToken(?string $protocols): ?string
{
    global $SESSION_SECRET;

    if ($protocols === null || $protocols === '') {
        return null;
    }

    $list = array_map('trim', explode(',', $protocols));

    foreach ($list as $proto) {
        if (str_starts_with($proto, 'access_token.')) {
            $token = substr($proto, strlen('access_token.'));
            try {
                JWT::decode($token, new Key($SESSION_SECRET, 'HS256'));
                return $proto;
            } catch (\Exception $e) {
                return null;
            }
        }
    }

    return null;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Reads and parses the [meta] section from deepgram.toml.
 *
 * @return array The metadata or an error structure
 */
function readMetadata(): array
{
    try {
        $tomlPath = __DIR__ . '/deepgram.toml';

        if (!file_exists($tomlPath)) {
            return ['error' => true, 'status' => 500, 'body' => [
                'error' => 'INTERNAL_SERVER_ERROR',
                'message' => 'deepgram.toml not found',
            ]];
        }

        $config = Toml::parseFile($tomlPath);
        $meta = $config['meta'] ?? null;

        if ($meta === null) {
            return ['error' => true, 'status' => 500, 'body' => [
                'error' => 'INTERNAL_SERVER_ERROR',
                'message' => 'Missing [meta] section in deepgram.toml',
            ]];
        }

        return ['error' => false, 'status' => 200, 'body' => $meta];
    } catch (\Exception $e) {
        echo "Error reading metadata: " . $e->getMessage() . "\n";
        return ['error' => true, 'status' => 500, 'body' => [
            'error' => 'INTERNAL_SERVER_ERROR',
            'message' => 'Failed to read metadata from deepgram.toml',
        ]];
    }
}

/**
 * Builds an HTTP response string to send through a Ratchet connection.
 *
 * @param int    $status  HTTP status code
 * @param array  $headers Associative array of headers
 * @param string $body    Response body
 * @return string Complete HTTP response
 */
function buildHttpResponse(int $status, array $headers, string $body): string
{
    $statusTexts = [
        200 => 'OK',
        204 => 'No Content',
        404 => 'Not Found',
        500 => 'Internal Server Error',
    ];
    $statusText = $statusTexts[$status] ?? 'Unknown';

    $response = "HTTP/1.1 {$status} {$statusText}\r\n";

    foreach ($headers as $name => $value) {
        $response .= "{$name}: {$value}\r\n";
    }

    $response .= "Content-Length: " . strlen($body) . "\r\n";
    $response .= "Connection: close\r\n";
    $response .= "\r\n";
    $response .= $body;

    return $response;
}

/**
 * Returns the standard CORS headers used on all HTTP responses.
 *
 * @return array CORS headers
 */
function corsHeaders(): array
{
    return [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers' => 'Content-Type, Authorization',
    ];
}

// ============================================================================
// HTTP API HANDLER - Handles REST endpoints via Ratchet's HttpServerInterface
// ============================================================================

/**
 * Handles HTTP requests for /api/session and /api/metadata.
 *
 * Ratchet's Router dispatches HTTP requests that do not match the WebSocket
 * route to this handler. It receives the PSR-7 request in onOpen and writes
 * a raw HTTP response string back through the Ratchet connection.
 */
class HttpApiHandler implements HttpServerInterface
{
    /**
     * Called when a new HTTP connection is opened.
     * Inspects the path, builds the response, writes it, and closes.
     *
     * @param ConnectionInterface $conn    The client connection
     * @param RequestInterface|null $request The HTTP request
     */
    public function onOpen(ConnectionInterface $conn, RequestInterface $request = null): void
    {
        $path = $request ? $request->getUri()->getPath() : '/';
        $method = $request ? $request->getMethod() : 'GET';

        $headers = array_merge(corsHeaders(), [
            'Content-Type' => 'application/json',
        ]);

        // CORS preflight
        if ($method === 'OPTIONS') {
            $conn->send(buildHttpResponse(204, corsHeaders(), ''));
            $conn->close();
            return;
        }

        // GET /api/session - Issue JWT session token
        if ($path === '/api/session' && $method === 'GET') {
            $token = createSessionToken();
            $body = json_encode(['token' => $token], JSON_UNESCAPED_SLASHES);
            $conn->send(buildHttpResponse(200, $headers, $body));
            $conn->close();
            return;
        }

        // GET /api/metadata - Project metadata from deepgram.toml
        if ($path === '/api/metadata' && $method === 'GET') {
            $result = readMetadata();
            $body = json_encode($result['body'], JSON_UNESCAPED_SLASHES);
            $conn->send(buildHttpResponse($result['status'], $headers, $body));
            $conn->close();
            return;
        }

        // GET /health - Simple health check
        if ($path === '/health' && $method === 'GET') {
            $body = json_encode(['status' => 'ok'], JSON_UNESCAPED_SLASHES);
            $conn->send(buildHttpResponse(200, $headers, $body));
            $conn->close();
            return;
        }

        // Not found
        $body = json_encode([
            'error' => 'NOT_FOUND',
            'message' => 'Not found',
        ], JSON_UNESCAPED_SLASHES);
        $conn->send(buildHttpResponse(404, $headers, $body));
        $conn->close();
    }

    public function onMessage(ConnectionInterface $from, $msg): void
    {
        // HTTP handler does not receive messages after the initial request
    }

    public function onClose(ConnectionInterface $conn): void
    {
        // Nothing to clean up for HTTP connections
    }

    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        echo "HTTP handler error: " . $e->getMessage() . "\n";
        $conn->close();
    }
}

// ============================================================================
// WEBSOCKET PROXY HANDLER - Transparent proxy to Deepgram Live STT API
// ============================================================================

/**
 * WebSocket proxy for Deepgram's Live Transcription API.
 *
 * On client connection:
 * 1. Validates JWT from Sec-WebSocket-Protocol header (access_token.<jwt>)
 * 2. Parses query params (model, language, encoding, sample_rate, channels, smart_format)
 * 3. Connects to Deepgram wss://api.deepgram.com/v1/listen with query params
 * 4. Forwards all messages bidirectionally (binary audio + JSON transcripts)
 *
 * On client disconnect: closes Deepgram connection
 * On Deepgram disconnect: closes client connection
 */
class LiveTranscriptionProxy implements MessageComponentInterface
{
    /** @var \React\EventLoop\LoopInterface ReactPHP event loop */
    private $loop;

    /** @var array<int, \Ratchet\Client\WebSocket> Map of connection ID to Deepgram WS */
    private $deepgramConnections = [];

    /** @var array<int, int> Client message counters for logging */
    private $clientMessageCounts = [];

    /** @var array<int, int> Deepgram message counters for logging */
    private $deepgramMessageCounts = [];

    public function __construct($loop)
    {
        $this->loop = $loop;
    }

    /**
     * Called when a client WebSocket connection opens.
     * Validates auth, parses query params, and opens upstream Deepgram connection.
     *
     * @param ConnectionInterface $conn The client connection
     */
    public function onOpen(ConnectionInterface $conn): void
    {
        $connId = $conn->resourceId;
        echo "Client connected to /api/live-transcription (conn #{$connId})\n";

        // Validate JWT from WebSocket subprotocol
        $protocols = $conn->httpRequest->getHeader('Sec-WebSocket-Protocol');
        $protocolStr = !empty($protocols) ? implode(', ', $protocols) : null;
        $validProto = validateWsToken($protocolStr);

        if ($validProto === null) {
            echo "WebSocket auth failed: invalid or missing token (conn #{$connId})\n";
            $conn->close(4401);
            return;
        }

        echo "WebSocket auth validated (conn #{$connId})\n";

        // Parse query parameters from client request
        $queryString = $conn->httpRequest->getUri()->getQuery();
        parse_str($queryString, $params);

        $model = $params['model'] ?? 'nova-3';
        $language = $params['language'] ?? 'en';
        $smartFormat = $params['smart_format'] ?? 'true';
        $encoding = $params['encoding'] ?? 'linear16';
        $sampleRate = $params['sample_rate'] ?? '16000';
        $channels = $params['channels'] ?? '1';

        // Build Deepgram WebSocket URL with query parameters
        $deepgramUrl = 'wss://api.deepgram.com/v1/listen'
            . '?model=' . urlencode($model)
            . '&language=' . urlencode($language)
            . '&smart_format=' . urlencode($smartFormat)
            . '&encoding=' . urlencode($encoding)
            . '&sample_rate=' . urlencode($sampleRate)
            . '&channels=' . urlencode($channels);

        echo "Connecting to Deepgram STT: model={$model}, language={$language}, "
            . "encoding={$encoding}, sample_rate={$sampleRate}, channels={$channels}\n";

        // Initialize message counters
        $this->clientMessageCounts[$connId] = 0;
        $this->deepgramMessageCounts[$connId] = 0;

        // Connect to Deepgram via pawl (Ratchet WebSocket client)
        global $apiKey;
        $connector = new \Ratchet\Client\Connector($this->loop);

        $connector($deepgramUrl, [], [
            'Authorization' => 'Token ' . $apiKey,
        ])->then(
            function (\Ratchet\Client\WebSocket $deepgramWs) use ($conn, $connId) {
                // Store the Deepgram connection
                $this->deepgramConnections[$connId] = $deepgramWs;

                echo "Connected to Deepgram STT API (conn #{$connId})\n";

                // Forward Deepgram messages to client
                $deepgramWs->on('message', function ($msg) use ($conn, $connId) {
                    $this->deepgramMessageCounts[$connId] =
                        ($this->deepgramMessageCounts[$connId] ?? 0) + 1;
                    $count = $this->deepgramMessageCounts[$connId];

                    $payload = $msg->getPayload();
                    $isBinary = $msg->isBinary();
                    $size = strlen($payload);

                    if ($count % 10 === 0 || !$isBinary) {
                        echo "<- Deepgram message #{$count} "
                            . "(binary: " . ($isBinary ? 'true' : 'false')
                            . ", size: {$size}) (conn #{$connId})\n";
                    }

                    // Forward to client
                    if ($isBinary) {
                        $conn->send(new \Ratchet\RFC6455\Messaging\Frame(
                            $payload,
                            true,
                            \Ratchet\RFC6455\Messaging\Frame::OP_BINARY
                        ));
                    } else {
                        $conn->send($payload);
                    }
                });

                // Handle Deepgram connection close
                $deepgramWs->on('close', function ($code = null, $reason = null) use ($conn, $connId) {
                    echo "Deepgram connection closed: {$code} {$reason} (conn #{$connId})\n";
                    unset($this->deepgramConnections[$connId]);
                    $conn->close();
                });

                // Handle Deepgram errors
                $deepgramWs->on('error', function (\Exception $e) use ($conn, $connId) {
                    echo "Deepgram WebSocket error: " . $e->getMessage()
                        . " (conn #{$connId})\n";
                    unset($this->deepgramConnections[$connId]);
                    $conn->close();
                });
            },
            function (\Exception $e) use ($conn, $connId) {
                echo "Failed to connect to Deepgram: " . $e->getMessage()
                    . " (conn #{$connId})\n";
                $conn->close(1011);
            }
        );
    }

    /**
     * Called when a client sends a message (binary audio data).
     * Forwards the message to Deepgram.
     *
     * @param ConnectionInterface $from The client connection
     * @param string              $msg  The message data
     */
    public function onMessage(ConnectionInterface $from, $msg): void
    {
        $connId = $from->resourceId;

        $this->clientMessageCounts[$connId] =
            ($this->clientMessageCounts[$connId] ?? 0) + 1;
        $count = $this->clientMessageCounts[$connId];

        if ($count % 100 === 0) {
            $size = strlen($msg);
            echo "-> Client message #{$count} (size: {$size}) (conn #{$connId})\n";
        }

        // Forward to Deepgram
        if (isset($this->deepgramConnections[$connId])) {
            $this->deepgramConnections[$connId]->send($msg);
        }
    }

    /**
     * Called when a client disconnects. Closes the upstream Deepgram connection.
     *
     * @param ConnectionInterface $conn The client connection
     */
    public function onClose(ConnectionInterface $conn): void
    {
        $connId = $conn->resourceId;
        echo "Client disconnected (conn #{$connId})\n";

        if (isset($this->deepgramConnections[$connId])) {
            $this->deepgramConnections[$connId]->close();
            unset($this->deepgramConnections[$connId]);
        }

        unset($this->clientMessageCounts[$connId]);
        unset($this->deepgramMessageCounts[$connId]);
    }

    /**
     * Called when a client connection encounters an error.
     *
     * @param ConnectionInterface $conn The client connection
     * @param \Exception          $e    The error
     */
    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        $connId = $conn->resourceId;
        echo "Client WebSocket error: " . $e->getMessage() . " (conn #{$connId})\n";

        if (isset($this->deepgramConnections[$connId])) {
            $this->deepgramConnections[$connId]->close();
            unset($this->deepgramConnections[$connId]);
        }

        $conn->close();
    }

    /**
     * Returns the number of active proxy connections.
     *
     * @return int Active connection count
     */
    public function getConnectionCount(): int
    {
        return count($this->deepgramConnections);
    }

    /**
     * Closes all active Deepgram connections (for graceful shutdown).
     */
    public function closeAll(): void
    {
        foreach ($this->deepgramConnections as $connId => $dgWs) {
            try {
                $dgWs->close();
            } catch (\Exception $e) {
                echo "Error closing Deepgram connection #{$connId}: "
                    . $e->getMessage() . "\n";
            }
        }
        $this->deepgramConnections = [];
    }
}

// ============================================================================
// SERVER SETUP - Ratchet IoServer + HttpServer + Router
// ============================================================================

$loop = Loop::get();

// Create the live transcription WebSocket proxy handler
$proxy = new LiveTranscriptionProxy($loop);

// Create WsServer wrapping the proxy, with subprotocol handling
$wsServer = new WsServer($proxy);
$wsServer->enableKeepAlive($loop, 30);

// Replace the handshake negotiator with one that accepts access_token.* subprotocols.
// Ratchet's default negotiator uses strict exact-match checking, which doesn't work
// with dynamic JWT-based subprotocols like access_token.<jwt>.
$customNegotiator = new class(new \Ratchet\RFC6455\Handshake\RequestVerifier()) extends \Ratchet\RFC6455\Handshake\ServerNegotiator {
    public function __construct(\Ratchet\RFC6455\Handshake\RequestVerifier $verifier) {
        parent::__construct($verifier);
        $this->setStrictSubProtocolCheck(false);
    }

    public function handshake(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface {
        $response = parent::handshake($request);

        // If handshake succeeded (101) but no subprotocol was set, echo back the access_token.* protocol
        if ($response->getStatusCode() === 101 && !$response->hasHeader('Sec-WebSocket-Protocol')) {
            $protocols = $request->getHeader('Sec-WebSocket-Protocol');
            $all = array_map('trim', explode(',', implode(',', $protocols)));
            foreach ($all as $proto) {
                if (str_starts_with($proto, 'access_token.')) {
                    $response = $response->withHeader('Sec-WebSocket-Protocol', $proto);
                    break;
                }
            }
        }

        return $response;
    }
};
$ref = new \ReflectionProperty($wsServer, 'handshakeNegotiator');
$ref->setAccessible(true);
$ref->setValue($wsServer, $customNegotiator);

// Set up Symfony routing for path-based dispatch
$routes = new RouteCollection();

// WebSocket route: /api/live-transcription
$routes->add('live-transcription', new Route(
    '/api/live-transcription',
    ['_controller' => $wsServer],
    [],    // requirements
    [],    // options
    null,  // host
    [],    // schemes
    ['GET'] // methods
));

// HTTP route: /api/session
$routes->add('session', new Route(
    '/api/session',
    ['_controller' => new HttpApiHandler()],
    [],
    [],
    null,
    [],
    ['GET', 'OPTIONS']
));

// HTTP route: /api/metadata
$routes->add('metadata', new Route(
    '/api/metadata',
    ['_controller' => new HttpApiHandler()],
    [],
    [],
    null,
    [],
    ['GET', 'OPTIONS']
));

// HTTP route: /health
$routes->add('health', new Route(
    '/health',
    ['_controller' => new HttpApiHandler()],
    [],
    [],
    null,
    [],
    ['GET', 'OPTIONS']
));

// Catch-all for other API paths (404 handler)
$routes->add('fallback', new Route(
    '/{path}',
    ['_controller' => new HttpApiHandler()],
    ['path' => '.*']
));

$urlMatcher = new UrlMatcher($routes, new RequestContext());
$router = new Router($urlMatcher);

// Build the server stack: IoServer -> HttpServer -> Router -> WsServer/HttpApiHandler
// Note: Do NOT pass $loop to factory() — on PHP 8.5+/ReactPHP, the explicit loop
// parameter breaks HTTP request dispatching. Loop::get() singleton is shared automatically.
$server = IoServer::factory(
    new HttpServer($router),
    (int)$PORT,
    $HOST
);

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

/**
 * Handles graceful shutdown on SIGTERM/SIGINT.
 * Closes all active WebSocket connections before stopping the event loop.
 */
$shutdownHandler = function (int $signal) use ($proxy, $server) {
    $signalName = $signal === SIGTERM ? 'SIGTERM' : 'SIGINT';
    echo "\n{$signalName} signal received: starting graceful shutdown...\n";

    // Close all active Deepgram connections
    $count = $proxy->getConnectionCount();
    echo "Closing {$count} active WebSocket connection(s)...\n";
    $proxy->closeAll();

    // Stop the server
    $server->socket->close();
    echo "Server stopped\n";

    // Stop the event loop
    $server->loop->stop();
    echo "Shutdown complete\n";
};

// Register signal handlers (only if pcntl extension is available)
if (function_exists('pcntl_signal')) {
    $server->loop->addSignal(SIGTERM, $shutdownHandler);
    $server->loop->addSignal(SIGINT, $shutdownHandler);
}

// ============================================================================
// START SERVER
// ============================================================================

echo "\n" . str_repeat("=", 70) . "\n";
echo "Backend API Server running at http://localhost:{$PORT}\n";
echo "\n";
echo "GET  /api/session\n";
echo "WS   /api/live-transcription (auth required)\n";
echo "GET  /api/metadata\n";
echo "GET  /health\n";
echo str_repeat("=", 70) . "\n\n";

$server->run();
