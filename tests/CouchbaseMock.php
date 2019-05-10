<?php
// vim: et ts=4 sw=4 sts=4

class CouchbaseMock {
    const VERSION = '1.5.23';

    private $jarPath;
    private $ctlServer;
    private $ctl;

    private $port;

    private static $instance = null;

    public static function get() {
        $port = getenv('CB_MOCK_CTL_PORT');
        if ($port) {
            if (self::$instance) {
                return self::$instance;
            }
            self::$instance = new CouchbaseMock((int)$port);
            return self::$instance;
        } else {
            return new CouchbaseMock();
        }
    }

    public function __construct($port = null) {
        $this->jarPath = join(DIRECTORY_SEPARATOR, [__DIR__, "CouchbaseMock.jar"]);
        $this->download();
        $this->port = $port;
    }

    public function download($version = CouchbaseMock::VERSION) {
        if (!file_exists($this->jarPath)) {
            $data = file_get_contents("http://packages.couchbase.com/clients/c/mock/CouchbaseMock-$version.jar");
            file_put_contents($this->jarPath, $data);
        }
    }

    private function startFork() {
        $this->ctlServer = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_bind($this->ctlServer, '127.0.0.1');
        socket_listen($this->ctlServer);
        socket_getsockname($this->ctlServer, $addr, $port);

        $this->pid = pcntl_fork();
        if ($this->pid) {
            $this->ctl = socket_accept($this->ctlServer);
        } else {
            $rc = pcntl_exec("/usr/bin/java", [
                "-jar", $this->jarPath,
                "--harakiri-monitor", "{$addr}:{$port}",
                "--port", "0",
                "--replicas", "2",
                "--nodes", "4",
                "--buckets", "default::"
            ]);
            if (!$rc) {
                exit(0);
            }
        }
    }

    private function startMonitor() {
        if ($this->ctl) {
            return;
        }
        $this->ctlServer = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_set_option($this->ctlServer, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_bind($this->ctlServer, '127.0.0.1', $this->port);
        socket_listen($this->ctlServer);
        $this->ctl = socket_accept($this->ctlServer);
    }

    public function start() {
        if ($this->port) {
            $this->startMonitor();
        } else {
            $this->startFork();
        }
    }

    public function stop() {
        if (!$this->port) {
            socket_close($this->ctl);
            socket_close($this->ctlServer);
        }
    }

    protected function send($payload) {
        socket_write($this->ctl, json_encode($payload) . "\n");
        $response = socket_read($this->ctl, 100000, PHP_NORMAL_READ);
        $json = strstr($response, '{');
        if ($json && strlen($json)) {
            $decoded = json_decode($json, TRUE);
            if (array_key_exists('error', $decoded)) {
                throw new Exception($decoded['error']);
            }
            return $decoded;
        }
        return [];
    }

    public function info() {
        return $this->send(['command' => 'MOCKINFO']);
    }

    public function keyInfo($key, $bucket = 'default') {
        return $this->send([
            'command' => 'KEYINFO',
            'payload' => [
                'Key' => $key,
                'Bucket' => $bucket
            ]
        ])['payload'];
    }

    public function masterForKey($key, $bucket = 'default') {
        $payload = $this->keyInfo($key, $bucket);
        for ($idx = 0; $idx < count($payload); $idx++) {
            if ($payload[$idx] && $payload[$idx]['Conf']['Type'] == 'master') {
                return $idx;
            }
        }
        return -1;
    }

    public function setCCCP($enabled = true) {
        $this->send([
            'command' => 'SET_CCCP',
            'payload' => [
                'enabled' => boolval($enabled)
            ]
        ]);
    }

    public function connectionString($options = []) {
        $resp = $this->send(['command' => 'GET_MCPORTS']);
        $connstr = "";
        foreach ($resp["payload"] as $port) {
            if ($connstr == "") {
                $connstr = "couchbase://127.0.0.1:{$port}";
            } else {
                $connstr .= ",127.0.0.1:{$port}";
            }
        }
        if (count($options)) {
            $connstr .= '?' . http_build_query($options);
        }
        return $connstr;
    }

    public function operationFailure($protocolCode, $count = 1, $bucket = 'default', $serverIndexes = []) {
        $this->send([
            'command' => 'OPFAIL',
            'payload' => [
                'code' => $protocolCode,
                'count' => $count,
                'bucket' => $bucket,
                'servers' => $serverIndexes
            ]
        ]);
    }

    public function operationFailureClear($bucket = 'default', $serverIndexes = []) {
        $this->operationFailure(0, -1, $bucket, $serverIndexes);
    }

    public function startRetryVerify($serverIndex, $bucket = 'default') {
        $this->send([
            'command' => 'START_RETRY_VERIFY',
            'payload' => [
                'bucket' => $bucket,
                'idx' => $serverIndex
            ]
        ]);
    }

    public function checkRetryVerify($protocolCode, $serverIndex, $protocolOpcode, $fuzzMs, $bucket = 'default') {
        $this->send([
            'command' => 'START_RETRY_VERIFY',
            'payload' => [
                'opcode' => $protocolOpcode,
                'errcode' => $protocolCode,
                'fuzz_ms' => $fuzzMs,
                'bucket' => $bucket,
                'idx' => $serverIndex
            ]
        ]);
    }
}
