<?php

namespace App\Services;

use App\Exceptions\ApiException;
use App\Models\Server;
use App\Models\User;
use App\Protocols\SingBox;
use App\Utils\Helper;
use Illuminate\Support\Facades\Cache;

class NodeHttpProbeService
{
    public function __construct(private NodeHttpProbeRunner $runner) {}

    public function latest(Server $server): ?array
    {
        $result = Cache::get('node-http-probe:result:'.$server->id);
        if (!is_array($result)) return null;
        $result['stale'] = ($result['fingerprint'] ?? '') !== $this->fingerprint($server)
            || time() - ($result['checked_at'] ?? 0) > (int) config('node_probe.fresh_seconds');
        unset($result['fingerprint']);
        return $result;
    }

    public function test(Server $server, ?User $admin): array
    {
        $lock = Cache::lock('node-http-probe:running', 30);
        if (!$lock->get()) throw new ApiException('已有节点正在测试，请稍后重试。', 429);
        try {
            if (!Cache::add('node-http-probe:cooldown:'.$server->id, true, 15)) {
                throw new ApiException('测试过于频繁，请 15 秒后重试。', 429);
            }
            $started = microtime(true);
            $result = $this->execute($server, $admin);
            $result += [
                'checked_at' => time(), 'target' => config('node_probe.target'), 'source' => 'panel',
                'duration_ms' => (int) round((microtime(true) - $started) * 1000),
                'core_version' => config('node_probe.version'), 'fingerprint' => $this->fingerprint($server),
            ];
            Cache::put('node-http-probe:result:'.$server->id, $result, (int) config('node_probe.retain_seconds'));
            unset($result['fingerprint']);
            return $result + ['stale' => false];
        } finally {
            $lock->release();
        }
    }

    private function execute(Server $server, ?User $admin): array
    {
        if (!$server->enabled) return $this->unavailable('node_disabled', '节点未启用。');
        if ($server->transfer_enable > 0 && $server->u + $server->d >= $server->transfer_enable) {
            return $this->unavailable('node_quota', '节点流量已用尽。');
        }
        // Use credentials already distributed to this node; never create or enable an account.
        $users = ServerService::getAvailableUsers($server);
        $candidate = $admin ? $users->firstWhere('id', $admin->id) : null;
        $candidate ??= $users->first();
        if (!$candidate) return $this->unavailable('no_test_user', '没有可用测试用户（需属于节点权限组、未封禁且套餐流量有效）。');
        $user = new User;
        $user->uuid = $candidate->uuid;
        $node = $server->toArray();
        $port = (string) $server->port;
        if (str_contains($port, '-')) {
            $node['ports'] = $port;
            $port = (string) Helper::randomPort($port);
        }
        $node['port'] = (int) $port;
        if ($node['port'] < 1 || $node['port'] > 65535) return $this->unavailable('invalid_port', '节点连接端口无效。');
        $node['password'] = $server->generateServerPassword($user);
        try {
            $protocol = new SingBox(['uuid' => $user->uuid], [$node], 'sing-box', config('node_probe.version'));
            $outbound = $protocol->buildProbeOutbound();
        } catch (\InvalidArgumentException $e) {
            return $this->unavailable('unsupported_protocol', '测试内核不支持该节点协议或传输配置。');
        }
        return $this->runner->run($outbound) + ['test_user_id' => (int) $candidate->id];
    }

    private function fingerprint(Server $server): string
    {
        return hash('sha256', json_encode([$server->host, $server->port, $server->type, $server->enabled,
            $server->protocol_settings, $server->cert_config, $server->group_ids, $server->updated_at, config('node_probe.version')]));
    }

    private function unavailable(string $code, string $message): array
    {
        return ['status' => 'unavailable', 'error_code' => $code, 'message' => $message, 'http_status' => null, 'latency_ms' => null];
    }
}
