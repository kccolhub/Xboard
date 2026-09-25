<?php

// Local end-to-end test, no production account or public network required.
// NODE_PROBE_SING_BOX=/path/to/sing-box-1.14.0 php tests/smoke/node-http-probe.php
require __DIR__.'/../../vendor/autoload.php';

use App\Services\NodeHttpProbeRunner;
use App\Protocols\SingBox;
use App\Utils\Certificate;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use Symfony\Component\Process\Process;

function check(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
function freePort(): int {
    $socket = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
    fclose($socket); return $port;
}
$app = new Container;
Container::setInstance($app);
$app->instance('app', $app);
$app->instance('cache', new CacheRepository(new ArrayStore));
Facade::setFacadeApplication($app);
$app->instance('config', new Repository(['node_probe' => require __DIR__.'/../../config/node_probe.php']));
config(['node_probe.binary' => getenv('NODE_PROBE_SING_BOX') ?: '/usr/local/bin/sing-box', 'node_probe.timeout' => 2]);
$directory = sys_get_temp_dir().'/xboard-probe-fixture-'.bin2hex(random_bytes(8));
mkdir($directory, 0700);
$core = null; $pid = null;
try {
    $cert = Certificate::generate('localhost');
    file_put_contents($directory.'/cert.pem', $cert['cert_content']);
    file_put_contents($directory.'/key.pem', $cert['key_content']);
    chmod($directory.'/key.pem', 0600);
    // Separate HTTPS target identity/trust from the node certificate. Use a
    // loopback IP so the fixture never depends on external localhost DNS.
    $targetCert = Certificate::generate('127.0.0.1');
    file_put_contents($directory.'/target.pem', $targetCert['cert_content']);
    file_put_contents($directory.'/target-key.pem', $targetCert['key_content']);
    chmod($directory.'/target-key.pem', 0600);
    config(['node_probe.ca_bundle' => $directory.'/target.pem']);
    $context = stream_context_create(['ssl' => ['local_cert' => $directory.'/target.pem', 'local_pk' => $directory.'/target-key.pem', 'verify_peer' => false]]);
    $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    $targetPort = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
    $pid = pcntl_fork();
    if ($pid === 0) {
        while ($connection = @stream_socket_accept($listener, 30)) {
            stream_set_timeout($connection, 3);
            if (@stream_socket_enable_crypto($connection, true, STREAM_CRYPTO_METHOD_TLS_SERVER)) {
                $line = fgets($connection);
                if ($line === false) { fclose($connection); continue; }
                while (($header = fgets($connection)) !== false && trim($header) !== '') {}
                file_put_contents($directory.'/requests', $line, FILE_APPEND);
                $status = str_contains($line, '/error') ? '503 Service Unavailable' : '204 No Content';
                fwrite($connection, "HTTP/1.1 $status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            fclose($connection);
        }
        exit(0);
    }
    check($pid > 0, 'Could not fork HTTPS fixture');
    fclose($listener);
    $trojanPort = freePort(); $hy2Port = freePort();
    $tls = ['enabled' => true, 'certificate_path' => $directory.'/cert.pem', 'key_path' => $directory.'/key.pem'];
    $ech = new Process([config('node_probe.binary'), 'generate', 'ech-keypair', 'ech.example.com']);
    $ech->mustRun();
    check(preg_match('/-----BEGIN ECH CONFIGS-----[\s\S]*?-----END ECH CONFIGS-----/', $ech->getOutput(), $echConfig) === 1, 'Missing ECH config');
    check(preg_match('/-----BEGIN ECH KEYS-----[\s\S]*?-----END ECH KEYS-----/', $ech->getOutput(), $echKey) === 1, 'Missing ECH key');
    $tls['ech'] = ['enabled' => true, 'key' => [$echKey[0]]];
    $server = ['log' => ['disabled' => true], 'inbounds' => [
        ['type' => 'trojan', 'listen' => '127.0.0.1', 'listen_port' => $trojanPort, 'users' => [['password' => 'fixture-password']], 'tls' => $tls],
        ['type' => 'hysteria2', 'listen' => '127.0.0.1', 'listen_port' => $hy2Port, 'users' => [['password' => 'fixture-password']], 'tls' => $tls,
            'obfs' => ['type' => 'salamander', 'password' => 'fixture-obfs']],
    ], 'outbounds' => [['type' => 'direct']]];
    file_put_contents($directory.'/server.json', json_encode($server));
    $core = new Process([config('node_probe.binary'), 'run', '-c', $directory.'/server.json'], $directory);
    $core->start();
    $ready = false;
    for ($i = 0; $i < 40; $i++) {
        $socket = @stream_socket_client("tcp://127.0.0.1:$trojanPort", $errno, $error, .1);
        if ($socket) { fclose($socket); $ready = true; break; }
        if (!$core->isRunning()) break;
        usleep(50000);
    }
    check($ready, 'Fixture proxy failed to start: '.$core->getErrorOutput());
    $runner = new class extends NodeHttpProbeRunner {
        public function networkFailure(int $errno, string $log): array
        {
            // Local fixtures use synthetic credentials only. Keep diagnostic
            // details here, never in the production runner/API response.
            return parent::networkFailure($errno, $log) + ['fixture_errno' => $errno, 'fixture_log' => $log];
        }
    };
    $before = glob(sys_get_temp_dir().'/xboard-probe-*');
    foreach (['trojan' => $trojanPort, 'hysteria2' => $hy2Port] as $type => $port) {
        $nodeTls = ['server_name' => 'localhost', 'allow_insecure' => false];
        $node = ['type' => $type === 'hysteria2' ? 'hysteria' : $type, 'name' => 'fixture',
            'host' => '127.0.0.1', 'port' => $port, 'cert_config' => ['cert_mode' => 'content'] + $cert,
            'protocol_settings' => $type === 'hysteria2'
                ? ['version' => 2, 'tls' => $nodeTls, 'obfs' => ['open' => true, 'type' => 'salamander', 'password' => 'fixture-obfs']]
                : ['tls_settings' => $nodeTls]];
        $outbound = (new SingBox(['uuid' => 'fixture-password'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
        check($outbound['tls']['insecure'] === false, "$type must verify the node certificate");
        config(['node_probe.target' => "https://127.0.0.1:$targetPort/ok"]);
        $result = $runner->run($outbound);
        check($result['status'] === 'success' && $result['http_status'] === 204, "$type success test: ".json_encode($result));
        $tlsKey = $type === 'hysteria2' ? 'tls' : 'tls_settings';
        $node['protocol_settings'][$tlsKey]['ech'] = ['enabled' => true, 'config' => $echConfig[0], 'key' => $echKey[0]];
        $outbound = (new SingBox(['uuid' => 'fixture-password'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
        check(!isset($outbound['tls']['ech']['key']), "$type leaked ECH private key");
        $result = $runner->run($outbound);
        check($result['status'] === 'success' && $result['http_status'] === 204, "$type ECH success test: ".json_encode($result));
        $hits = file_get_contents($directory.'/requests');
        foreach (['missing-trust', 'wrong-cert', 'wrong-sni'] as $case) {
            $bad = $outbound;
            if ($case === 'missing-trust') unset($bad['tls']['certificate']);
            if ($case === 'wrong-cert') $bad['tls']['certificate'] = [Certificate::generate('localhost')['cert_content']];
            if ($case === 'wrong-sni') $bad['tls']['server_name'] = 'wrong.example';
            $result = $runner->run($bad);
            check($result['status'] === 'failed' && $result['error_code'] === 'node_tls_certificate', "$type $case test: ".json_encode($result));
            check(file_get_contents($directory.'/requests') === $hits, "$type $case bypassed node TLS verification");
        }
        config(['node_probe.target' => "https://127.0.0.1:$targetPort/error"]);
        $result = $runner->run($outbound);
        check($result['status'] === 'failed' && $result['http_status'] === 503, "$type status test: ".json_encode($result));
        config(['node_probe.ca_bundle' => null]);
        $result = $runner->run($outbound);
        check($result['status'] === 'failed' && $result['error_code'] === 'target_tls_certificate', "$type TLS verification test: ".json_encode($result));
        config(['node_probe.ca_bundle' => $directory.'/target.pem']);
        $hits = file_get_contents($directory.'/requests');
        $outbound['password'] = 'wrong-password';
        $result = $runner->run($outbound);
        check($result['status'] === 'failed' && $result['http_status'] === null, "$type auth test: ".json_encode($result));
        check(file_get_contents($directory.'/requests') === $hits, "$type bypassed the proxy on authentication failure");
        echo "$type: HTTPS 204 (with/without ECH), HTTP 503, strict node trust, wrong-cert/SNI, target TLS, wrong-auth/no-direct-fallback passed\n";
    }
    check(glob(sys_get_temp_dir().'/xboard-probe-*') === $before, 'Probe temporary files leaked');
    echo "Probe cleanup passed\n";
} finally {
    if ($core && $core->isRunning()) $core->stop(.2);
    if ($pid > 0) { posix_kill($pid, SIGTERM); pcntl_waitpid($pid, $status); }
    foreach (['cert.pem', 'key.pem', 'target.pem', 'target-key.pem', 'server.json', 'requests'] as $file) if (is_file($directory.'/'.$file)) unlink($directory.'/'.$file);
    rmdir($directory);
}
