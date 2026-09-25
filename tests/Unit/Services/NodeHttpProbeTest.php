<?php

namespace Tests\Unit\Services;

use App\Exceptions\ApiException;
use App\Models\Server;
use App\Models\User;
use App\Http\Middleware\Admin;
use App\Protocols\SingBox;
use App\Services\NodeHttpProbeRunner;
use App\Services\NodeHttpProbeService;
use App\Utils\Certificate;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Config\Repository as Config;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;

class NodeHttpProbeTest extends TestCase
{
    private Container $container;
    private Manager $db;

    protected function setUp(): void
    {
        $this->container = new Container;
        Container::setInstance($this->container);
        $this->container->instance('app', $this->container);
        $this->container->instance('config', new Config(['node_probe' => require __DIR__.'/../../../config/node_probe.php']));
        $this->container->instance('cache', new Repository(new ArrayStore));
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($this->container);
        $this->db = new Manager($this->container);
        $this->db->addConnection(['driver' => 'sqlite', 'database' => ':memory:']);
        $this->db->bootEloquent();
        $this->db->getConnection()->getSchemaBuilder()->create('v2_user', function (Blueprint $table) {
            $table->increments('id'); $table->string('uuid'); $table->integer('group_id');
            $table->integer('u')->default(0); $table->integer('d')->default(0); $table->integer('transfer_enable')->default(10000);
            $table->integer('expired_at')->nullable(); $table->boolean('banned')->default(false);
            $table->integer('speed_limit')->nullable(); $table->integer('device_limit')->nullable();
        });
    }

    protected function tearDown(): void
    {
        $this->db->getConnection()->disconnect();
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Container::setInstance(null);
    }

    private function node(): Server
    {
        return (new Server)->forceFill(['id' => 17, 'name' => 'fixture', 'type' => 'trojan', 'host' => '192.0.2.1',
            'port' => '443', 'enabled' => true, 'group_ids' => ['1'], 'protocol_settings' => ['tls_settings' => ['allow_insecure' => false]]]);
    }

    private function addUser(int $id, array $extra = []): User
    {
        $data = $extra + ['id' => $id, 'uuid' => "secret-$id", 'group_id' => 1];
        $this->db->getConnection()->table('v2_user')->insert($data);
        return (new User)->forceFill($data);
    }

    public function test_uses_eligible_admin_and_caches_only_safe_result(): void
    {
        $this->addUser(1);
        $admin = $this->addUser(2);
        $runner = $this->createMock(NodeHttpProbeRunner::class);
        $runner->expects($this->once())->method('run')->with($this->callback(fn ($outbound) =>
            $outbound['type'] === 'trojan' && $outbound['password'] === 'secret-2' && $outbound['tag'] === 'probe'))
            ->willReturn(['status' => 'success', 'http_status' => 204, 'latency_ms' => 123]);
        $service = new NodeHttpProbeService($runner);
        $result = $service->test($this->node(), $admin);
        $this->assertSame('success', $result['status']);
        $this->assertSame(2, $result['test_user_id']);
        $this->assertFalse($result['stale']);
        $this->assertStringNotContainsString('secret-', json_encode($result));
        $this->assertSame($result, $service->latest($this->node()));
        $this->assertFalse(Cache::has('node-http-probe:running'));
    }

    public function test_excludes_expired_banned_exhausted_and_wrong_group_users(): void
    {
        $this->addUser(1, ['banned' => true]);
        $this->addUser(2, ['expired_at' => time() - 10]);
        $this->addUser(3, ['transfer_enable' => 0]);
        $this->addUser(4, ['group_id' => 2]);
        $runner = $this->createMock(NodeHttpProbeRunner::class);
        $runner->expects($this->never())->method('run');
        $result = (new NodeHttpProbeService($runner))->test($this->node(), null);
        $this->assertSame('no_test_user', $result['error_code']);
        $this->assertSame('unavailable', $result['status']);
    }

    public function test_falls_back_to_an_existing_eligible_user_without_creating_one(): void
    {
        $admin = $this->addUser(1, ['group_id' => 2]);
        $this->addUser(2);
        $runner = $this->createMock(NodeHttpProbeRunner::class);
        $runner->method('run')->willReturn(['status' => 'success']);
        $result = (new NodeHttpProbeService($runner))->test($this->node(), $admin);
        $this->assertSame(2, $result['test_user_id']);
        $this->assertSame(2, $this->db->getConnection()->table('v2_user')->count());
    }

    public function test_disabled_node_is_not_reported_as_network_failure(): void
    {
        $node = $this->node(); $node->enabled = false;
        $runner = $this->createMock(NodeHttpProbeRunner::class);
        $runner->expects($this->never())->method('run');
        $result = (new NodeHttpProbeService($runner))->test($node, null);
        $this->assertSame('node_disabled', $result['error_code']);
    }

    public function test_lock_prevents_concurrent_tests(): void
    {
        $lock = Cache::lock('node-http-probe:running', 30); $lock->get();
        $this->expectException(ApiException::class);
        $this->expectExceptionCode(429);
        (new NodeHttpProbeService(new NodeHttpProbeRunner))->test($this->node(), null);
    }

    public function test_cooldown_prevents_repeated_tests_and_releases_lock(): void
    {
        Cache::add('node-http-probe:cooldown:17', true, 15);
        try {
            (new NodeHttpProbeService(new NodeHttpProbeRunner))->test($this->node(), null);
            $this->fail('Expected cooldown');
        } catch (ApiException $e) {
            $this->assertSame(429, $e->getCode());
            $this->assertTrue(Cache::lock('node-http-probe:running', 30)->get());
        }
    }

    public function test_previous_result_becomes_stale_after_configuration_change_or_age(): void
    {
        $service = new NodeHttpProbeService(new NodeHttpProbeRunner);
        $service->test($this->node(), null);
        $node = $this->node(); $node->host = '192.0.2.2';
        $this->assertTrue($service->latest($node)['stale']);
        $node = $this->node(); $node->cert_config = ['cert_mode' => 'content', 'cert_content' => 'rotated'];
        $this->assertTrue($service->latest($node)['stale']);
        $cached = Cache::get('node-http-probe:result:17');
        $cached['checked_at'] = time() - 301;
        Cache::put('node-http-probe:result:17', $cached, 86400);
        $this->assertTrue($service->latest($this->node())['stale']);
    }

    public function test_probe_configuration_has_one_proxy_no_direct_no_tun_and_authenticates_loopback(): void
    {
        $config = (new NodeHttpProbeRunner)->configuration(['type' => 'trojan', 'detour' => 'direct'], 12345, 'private');
        $this->assertCount(1, $config['outbounds']);
        $this->assertArrayNotHasKey('detour', $config['outbounds'][0]);
        $this->assertSame('probe', $config['route']['final']);
        $this->assertSame('socks', $config['inbounds'][0]['type']);
        $this->assertSame('127.0.0.1', $config['inbounds'][0]['listen']);
        $this->assertSame('private', $config['inbounds'][0]['users'][0]['password']);
        $this->assertArrayNotHasKey('rule_set', $config['route']);
    }

    public function test_direct_outbound_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new NodeHttpProbeRunner)->configuration(['type' => 'direct'], 12345, 'private');
    }

    public function test_network_errors_are_classified_without_exposing_logs(): void
    {
        $result = (new NodeHttpProbeRunner)->networkFailure(28, 'secret-password authentication failed');
        $this->assertSame('authentication', $result['error_code']);
        $this->assertStringNotContainsString('secret-password', json_encode($result));
        $this->assertSame('timeout', (new NodeHttpProbeRunner)->networkFailure(28, '')['error_code']);
        $node = (new NodeHttpProbeRunner)->networkFailure(0, 'secret-password x509: certificate invalid');
        $this->assertSame('node_tls_certificate', $node['error_code']);
        $this->assertStringNotContainsString('secret-password', json_encode($node));
        // cURL validates the target HTTPS leg, not the node TLS leg. Its errno
        // takes priority over unrelated sing-box log lines.
        $this->assertSame('target_tls_certificate', (new NodeHttpProbeRunner)->networkFailure(60, 'certificate log')['error_code']);
        $this->assertSame('target_tls_ca', (new NodeHttpProbeRunner)->networkFailure(77, '')['error_code']);
    }

    public function test_probe_trusts_only_public_content_certificate_without_changing_sni_or_insecure(): void
    {
        $cert = Certificate::generate('node.example');
        foreach (['trojan', 'hysteria', 'tuic', 'anytls', 'vmess', 'vless', 'http'] as $type) {
            $tls = ['server_name' => 'node.example', 'allow_insecure' => false];
            $settings = ['tls' => 1, 'tls_settings' => $tls];
            if (in_array($type, ['hysteria', 'tuic', 'anytls'], true)) {
                $settings = ['version' => 2, 'tls' => $tls];
            }
            $node = ['type' => $type, 'name' => 'node', 'host' => '192.0.2.1', 'port' => 443,
                'protocol_settings' => $settings, 'cert_config' => ['cert_mode' => 'content'] + $cert];
            // Even accidentally concatenated private material must not enter the config.
            $node['cert_config']['cert_content'] .= $cert['key_content'];
            $build = fn(array $node) => (new SingBox(['uuid' => 'user-secret'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
            $outbound = $build($node);
            $this->assertSame([trim($cert['cert_content'])], $outbound['tls']['certificate'], $type);
            $this->assertSame('node.example', $outbound['tls']['server_name'], $type);
            $this->assertFalse($outbound['tls']['insecure'], $type);
            $this->assertStringNotContainsString('PRIVATE KEY', json_encode($outbound), $type);
            // File/ACME certificate modes still use normal public CA verification.
            $node['cert_config'] = ['cert_mode' => 'file', 'cert_content' => 'not a PEM'];
            $this->assertArrayNotHasKey('certificate', $build($node)['tls'], $type);
        }
    }

    public function test_probe_does_not_apply_content_trust_to_reality_or_plaintext(): void
    {
        foreach (['trojan', 'vless', 'http'] as $type) {
            $node = ['type' => $type, 'name' => 'node', 'host' => '192.0.2.1', 'port' => 443,
                'protocol_settings' => ['tls' => $type === 'http' ? 0 : 2,
                    'reality_settings' => ['server_name' => 'node.example', 'public_key' => 'key', 'short_id' => '01']],
                'cert_config' => ['cert_mode' => 'content', 'cert_content' => 'irrelevant invalid PEM']];
            $result = (new SingBox(['uuid' => 'user-secret'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
            $this->assertArrayNotHasKey('certificate', $result['tls'] ?? []);
        }
    }

    public function test_invalid_content_certificate_fails_closed(): void
    {
        $node = $this->node()->toArray();
        $node['cert_config'] = ['cert_mode' => 'content', 'cert_content' => 'invalid'];
        $this->expectException(\InvalidArgumentException::class);
        (new SingBox(['uuid' => 'user-secret'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
    }

    public function test_hysteria_obfuscation_tls_and_password_match_subscription_builder(): void
    {
        $node = ['type' => 'hysteria', 'name' => 'node', 'host' => '192.0.2.1', 'port' => 443,
            'protocol_settings' => ['version' => 2, 'tls' => ['server_name' => 'node.example', 'allow_insecure' => true],
                'obfs' => ['open' => true, 'type' => 'salamander', 'password' => 'obfs-secret']]];
        $result = (new SingBox(['uuid' => 'user-secret'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
        $this->assertSame('hysteria2', $result['type']);
        $this->assertSame('user-secret', $result['password']);
        $this->assertSame('obfs-secret', $result['obfs']['password']);
        $this->assertSame('node.example', $result['tls']['server_name']);
    }

    public function test_unsupported_transport_does_not_fall_back_to_direct(): void
    {
        $node = ['type' => 'vless', 'protocol_settings' => ['network' => 'xhttp']];
        $this->expectException(\InvalidArgumentException::class);
        (new SingBox(['uuid' => 'user-secret'], [$node], 'sing-box', '1.14.0'))->buildProbeOutbound();
    }

    public function test_missing_runtime_is_reported_as_unavailable(): void
    {
        config(['node_probe.binary' => '/nonexistent/sing-box']);
        $this->assertSame('runtime_missing', (new NodeHttpProbeRunner)->run(['type' => 'trojan'])['error_code']);
    }

    public function test_admin_middleware_rejects_anonymous_and_regular_users(): void
    {
        $factory = $this->createMock(\Illuminate\Contracts\Routing\ResponseFactory::class);
        $factory->method('json')->willReturnCallback(fn ($data, $status) => new \Illuminate\Http\JsonResponse($data, $status));
        $this->container->instance(\Illuminate\Contracts\Routing\ResponseFactory::class, $factory);
        foreach ([null, (new User)->forceFill(['is_admin' => false])] as $user) {
            $guard = $this->createMock(\Illuminate\Contracts\Auth\Guard::class);
            $guard->method('user')->willReturn($user);
            $auth = $this->createMock(\Illuminate\Contracts\Auth\Factory::class);
            $auth->expects($this->once())->method('guard')->with('sanctum')->willReturn($guard);
            $this->container->instance('auth', $auth);
            Facade::clearResolvedInstance('auth');
            $response = (new Admin)->handle(\Illuminate\Http\Request::create('/api/v2/admin/server/manage/testHttp', 'POST'), function () {
                $this->fail('Unauthenticated or regular user reached admin endpoint');
            });
            $this->assertSame(403, $response->getStatusCode());
        }
    }
}
