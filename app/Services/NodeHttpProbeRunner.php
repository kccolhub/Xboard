<?php

namespace App\Services;

use Symfony\Component\Process\Process;

/** An isolated, short-lived sing-box + authenticated loopback SOCKS probe. */
class NodeHttpProbeRunner
{
    public function run(array $outbound): array
    {
        $binary = config('node_probe.binary');
        if (!is_string($binary) || !is_executable($binary) || !extension_loaded('curl')) {
            return $this->failure('unavailable', 'runtime_missing', '面板未安装 sing-box 测试内核或 PHP cURL。');
        }
        $process = null;
        $directory = null;
        try {
            $version = new Process([$binary, 'version'], null, null, null, 2);
            $version->run();
            if (!$version->isSuccessful() || !str_contains($version->getOutput(), 'sing-box version '.config('node_probe.version')."\n")) {
                return $this->failure('unavailable', 'runtime_version', '测试内核版本不符，需要 sing-box '.config('node_probe.version').'。');
            }
            $directory = sys_get_temp_dir().'/xboard-probe-'.bin2hex(random_bytes(16));
            if (!mkdir($directory, 0700)) {
                throw new \RuntimeException('Cannot create private probe directory');
            }
            $socket = @stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
            if (!$socket) throw new \RuntimeException('Cannot allocate loopback port');
            $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
            fclose($socket);
            $secret = bin2hex(random_bytes(24));
            $config = $this->configuration($outbound, $port, $secret);
            $path = $directory.'/config.json';
            if (file_put_contents($path, json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)) === false) {
                throw new \RuntimeException('Cannot write probe configuration');
            }
            chmod($path, 0600);
            $process = new Process([$binary, 'run', '--disable-color', '-c', $path], $directory, [
                'HTTP_PROXY' => false, 'HTTPS_PROXY' => false, 'ALL_PROXY' => false,
                'http_proxy' => false, 'https_proxy' => false, 'all_proxy' => false,
            ], null, 20);
            $process->start();
            $ready = false;
            $deadline = microtime(true) + 3;
            do {
                if (!$process->isRunning()) break;
                $socket = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $error, 0.1);
                if ($socket) { fclose($socket); $ready = true; break; }
                usleep(50000);
            } while (microtime(true) < $deadline);
            if (!$ready || !$process->isRunning()) {
                return $this->failure('unavailable', 'runtime_start', '测试内核启动失败，请检查节点协议配置及内核支持。');
            }
            // SOCKS authentication prevents a port allocation race from testing another local proxy.
            $curl = curl_init(config('node_probe.target'));
            $bytes = 0;
            curl_setopt_array($curl, [
                CURLOPT_PROXY => "127.0.0.1:$port",
                CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5_HOSTNAME,
                CURLOPT_PROXYUSERPWD => 'probe:'.$secret,
                CURLOPT_NOPROXY => '',
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => (int) config('node_probe.timeout'),
                CURLOPT_TIMEOUT => (int) config('node_probe.timeout'),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_USERAGENT => 'Xboard-Node-HTTP-Probe/1.0',
                CURLOPT_WRITEFUNCTION => static function ($handle, string $body) use (&$bytes): int {
                    $bytes += strlen($body);
                    return $bytes <= 65536 ? strlen($body) : 0;
                },
            ]);
            if ($ca = config('node_probe.ca_bundle')) curl_setopt($curl, CURLOPT_CAINFO, $ca);
            try {
                $ok = curl_exec($curl);
                $code = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
                $elapsed = (int) round(curl_getinfo($curl, CURLINFO_TOTAL_TIME) * 1000);
                $errno = curl_errno($curl);
            } finally {
                unset($curl);
            }
            if ($ok !== false && $code === (int) config('node_probe.expected_status')) {
                return ['status' => 'success', 'http_status' => $code, 'latency_ms' => $elapsed,
                    'error_code' => null, 'message' => '代理 HTTPS 请求成功。'];
            }
            if ($code > 0) {
                return array_merge($this->failure('failed', 'http_status', '目标返回了非预期 HTTP 状态码。'), [
                    'http_status' => $code, 'latency_ms' => $elapsed,
                ]);
            }
            return $this->networkFailure($errno, $process->getErrorOutput());
        } catch (\Throwable $e) {
            // Never return raw process commands/logs: they may contain node credentials.
            return $this->failure('unavailable', 'probe_internal', '测试执行失败，请检查面板运行环境。');
        } finally {
            if ($process !== null && $process->isRunning()) $process->stop(0.2);
            if ($directory !== null) {
                if (is_file($directory.'/config.json')) unlink($directory.'/config.json');
                if (is_dir($directory)) rmdir($directory);
            }
        }
    }

    public function configuration(array $outbound, int $port, string $secret): array
    {
        if (!in_array($outbound['type'] ?? '', ['shadowsocks', 'trojan', 'vmess', 'vless', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'socks', 'http'], true)) {
            throw new \InvalidArgumentException('Probe requires one real proxy outbound');
        }
        $outbound['tag'] = 'probe';
        unset($outbound['detour']);
        return [
            'log' => ['level' => 'error', 'timestamp' => false],
            'dns' => ['servers' => [['type' => 'local', 'tag' => 'local']], 'strategy' => 'ipv4_only'],
            'inbounds' => [['type' => 'socks', 'tag' => 'probe-in', 'listen' => '127.0.0.1', 'listen_port' => $port,
                'users' => [['username' => 'probe', 'password' => $secret]]]],
            'outbounds' => [$outbound],
            'route' => ['final' => 'probe', 'default_domain_resolver' => ['server' => 'local', 'strategy' => 'ipv4_only']],
        ];
    }

    public function networkFailure(int $errno, string $log): array
    {
        $log = strtolower($log);
        [$code, $message] = match (true) {
            $errno === 60 => ['target_tls_certificate', '目标网站 HTTPS 证书验证失败（非节点证书），请检查面板 CA 与目标证书。'],
            $errno === 77 => ['target_tls_ca', '面板无法读取目标网站 HTTPS 校验所需的 CA 证书文件。'],
            str_contains($log, 'certificate'), str_contains($log, 'x509:') => ['node_tls_certificate', '节点 TLS 证书验证失败，请检查节点证书、有效期及 SNI 是否匹配。'],
            str_contains($log, 'authentication'), str_contains($log, 'unauthorized') => ['authentication', '节点认证失败。'],
            str_contains($log, 'refused') => ['connection_refused', '节点拒绝连接。'],
            str_contains($log, 'resolve'), str_contains($log, 'no such host') => ['dns', '域名解析失败。'],
            $errno === 28, str_contains($log, 'timeout'), str_contains($log, 'deadline') => ['timeout', '代理连接或 HTTPS 请求超时。'],
            default => ['proxy_connection', '代理握手或 HTTPS 连接失败。'],
        };
        return $this->failure('failed', $code, $message);
    }

    private function failure(string $status, string $code, string $message): array
    {
        return ['status' => $status, 'error_code' => $code, 'message' => $message, 'http_status' => null, 'latency_ms' => null];
    }
}
