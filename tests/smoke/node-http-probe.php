<?php

// Local end-to-end test, no production account or public network required.
// NODE_PROBE_SING_BOX=/path/to/sing-box-1.14.0 php tests/smoke/node-http-probe.php
require __DIR__.'/../../vendor/autoload.php';

use App\Services\NodeHttpProbeRunner;
use App\Utils\Certificate;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Symfony\Component\Process\Process;

function check(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
function freePort(): int {
    $socket = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
    fclose($socket); return $port;
}
$app = new Container;
Container::setInstance($app);
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
    config(['node_probe.ca_bundle' => $directory.'/cert.pem']);
    $context = stream_context_create(['ssl' => ['local_cert' => $directory.'/cert.pem', 'local_pk' => $directory.'/key.pem', 'verify_peer' => false]]);
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
    $runner = new NodeHttpProbeRunner;
    $before = glob(sys_get_temp_dir().'/xboard-probe-*');
    foreach (['trojan' => $trojanPort, 'hysteria2' => $hy2Port] as $type => $port) {
        $outbound = ['type' => $type, 'server' => '127.0.0.1', 'server_port' => $port, 'password' => 'fixture-password', 'tls' => ['enabled' => true, 'insecure' => true]];
        if ($type === 'hysteria2') $outbound['obfs'] = ['type' => 'salamander', 'password' => 'fixture-obfs'];
        config(['node_probe.target' => "https://localhost:$targetPort/ok"]);
        $result = $runner->run($outbound);
        check($result['status'] === 'success' && $result['http_status'] === 204, "$type success test: ".json_encode($result));
        config(['node_probe.target' => "https://localhost:$targetPort/error"]);
        $result = $runner->run($outbound);
        check($result['status'] === 'failed' && $result['http_status'] === 503, "$type status test: ".json_encode($result));
        config(['node_probe.ca_bundle' => null]);
        $result = $runner->run($outbound);
        check($result['status'] === 'failed' && $result['error_code'] === 'tls_certificate', "$type TLS verification test: ".json_encode($result));
        config(['node_probe.ca_bundle' => $directory.'/cert.pem']);
        $hits = file_get_contents($directory.'/requests');
        $outbound['password'] = 'wrong-password';
        $result = $runner->run($outbound);
        check($result['status'] === 'failed' && $result['http_status'] === null, "$type auth test: ".json_encode($result));
        check(file_get_contents($directory.'/requests') === $hits, "$type bypassed the proxy on authentication failure");
        echo "$type: HTTPS 204, HTTP 503, TLS verification, wrong-auth/no-direct-fallback passed\n";
    }
    check(glob(sys_get_temp_dir().'/xboard-probe-*') === $before, 'Probe temporary files leaked');
    echo "Probe cleanup passed\n";
} finally {
    if ($core && $core->isRunning()) $core->stop(.2);
    if ($pid > 0) { posix_kill($pid, SIGTERM); pcntl_waitpid($pid, $status); }
    foreach (['cert.pem', 'key.pem', 'server.json', 'requests'] as $file) if (is_file($directory.'/'.$file)) unlink($directory.'/'.$file);
    rmdir($directory);
}
