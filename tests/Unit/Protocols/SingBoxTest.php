<?php

namespace Tests\Unit\Protocols;

use App\Protocols\SingBox;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class SingBoxTest extends TestCase
{
    public function test_it_removes_dns_detour_to_an_empty_direct_outbound(): void
    {
        $config = [
            'dns' => [
                'servers' => [
                    ['tag' => 'local', 'type' => 'https', 'server' => '223.5.5.5', 'detour' => 'direct'],
                    ['tag' => 'remote', 'type' => 'https', 'server' => '1.1.1.1', 'detour' => 'proxy'],
                ],
            ],
            'outbounds' => [
                ['tag' => 'direct', 'type' => 'direct'],
                ['tag' => 'proxy', 'type' => 'selector', 'outbounds' => ['node']],
            ],
        ];

        $result = $this->normalizeDnsDetours($config);

        $this->assertArrayNotHasKey('detour', $result['dns']['servers'][0]);
        $this->assertSame('proxy', $result['dns']['servers'][1]['detour']);
    }

    public function test_it_preserves_dns_detour_to_a_configured_direct_outbound(): void
    {
        $config = [
            'dns' => [
                'servers' => [
                    ['tag' => 'local', 'type' => 'https', 'server' => '223.5.5.5', 'detour' => 'direct-vpn'],
                ],
            ],
            'outbounds' => [
                ['tag' => 'direct-vpn', 'type' => 'direct', 'bind_interface' => 'en0'],
            ],
        ];

        $result = $this->normalizeDnsDetours($config);

        $this->assertSame('direct-vpn', $result['dns']['servers'][0]['detour']);
    }

    public function test_it_upgrades_rule_set_downloads_to_a_direct_http_client(): void
    {
        $config = [
            'route' => [
                'rule_set' => [[
                    'tag' => 'geosite-cn',
                    'type' => 'remote',
                    'download_detour' => '自动选择',
                ]],
            ],
        ];

        $result = $this->invokeConfigMethod($config, 'upgradeRuleSetHttpClient');

        $this->assertSame('rule-set-direct', $result['route']['default_http_client']);
        $this->assertSame('rule-set-direct', $result['route']['rule_set'][0]['http_client']);
        $this->assertArrayNotHasKey('download_detour', $result['route']['rule_set'][0]);
        $this->assertSame('rule-set-direct', $result['http_clients'][0]['tag']);
        $this->assertArrayNotHasKey('detour', $result['http_clients'][0]);
    }

    public function test_it_downgrades_rule_set_http_client_for_pre_114_clients(): void
    {
        $config = [
            'http_clients' => [['tag' => 'rule-set-direct', 'engine' => 'go']],
            'route' => [
                'default_http_client' => 'rule-set-direct',
                'rule_set' => [[
                    'tag' => 'geoip-cn',
                    'type' => 'remote',
                    'http_client' => 'rule-set-direct',
                ]],
            ],
        ];

        $result = $this->invokeConfigMethod($config, 'downgradeRuleSetHttpClient');

        $this->assertArrayNotHasKey('http_clients', $result);
        $this->assertArrayNotHasKey('default_http_client', $result['route']);
        $this->assertArrayNotHasKey('http_client', $result['route']['rule_set'][0]);
        $this->assertSame('direct', $result['route']['rule_set'][0]['download_detour']);
    }

    public function test_it_rewrites_official_rule_sets_to_the_panel_host(): void
    {
        $config = [
            'route' => [
                'rule_set' => [
                    [
                        'tag' => 'geosite-cn',
                        'url' => 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
                    ],
                    [
                        'tag' => 'custom',
                        'url' => 'https://rules.example/custom.srs',
                    ],
                ],
            ],
        ];

        $result = $this->invokeConfigMethod(
            $config,
            'replaceOfficialRuleSetUrls',
            ['https://panel.example']
        );

        $this->assertSame('https://panel.example/rules/geosite-cn.srs', $result['route']['rule_set'][0]['url']);
        $this->assertSame('https://rules.example/custom.srs', $result['route']['rule_set'][1]['url']);
    }

    public function test_it_forces_ipv4_only_for_dns_resolution_and_tun_addresses(): void
    {
        $config = [
            'dns' => [
                'strategy' => 'prefer_ipv4',
                'rules' => [['action' => 'route', 'server' => 'local']],
            ],
            'inbounds' => [
                ['tag' => 'tun-in', 'type' => 'tun', 'domain_strategy' => 'prefer_ipv4', 'address' => ['172.19.0.1/30', '2001:db8::1/64']],
            ],
            'outbounds' => [
                ['tag' => 'proxy', 'type' => 'vmess', 'domain_strategy' => 'prefer_ipv4'],
            ],
            'route' => [
                'rules' => [['inbound' => 'tun-in', 'action' => 'resolve', 'strategy' => 'prefer_ipv4']],
            ],
        ];

        $result = $this->invokeConfigMethod($config, 'forceIpv4Only', [$config]);

        $this->assertSame('ipv4_only', $result['dns']['strategy']);
        $this->assertSame('ipv4_only', $result['dns']['rules'][0]['strategy']);
        $this->assertSame('ipv4_only', $result['route']['default_domain_resolver']['strategy']);
        $this->assertSame(['172.19.0.1/30'], $result['inbounds'][0]['address']);
        $this->assertSame('ipv4_only', $result['inbounds'][0]['domain_strategy']);
        $this->assertSame('ipv4_only', $result['route']['rules'][0]['strategy']);
        $this->assertSame('ipv4_only', $result['outbounds'][0]['domain_strategy']);
    }

    private function normalizeDnsDetours(array $config): array
    {
        return $this->invokeConfigMethod($config, 'removeEmptyDirectDnsDetours');
    }

    private function invokeConfigMethod(array $config, string $methodName, array $arguments = []): array
    {
        $reflection = new ReflectionClass(SingBox::class);
        /** @var SingBox $protocol */
        $protocol = $reflection->newInstanceWithoutConstructor();

        $configProperty = $reflection->getProperty('config');
        $configProperty->setValue($protocol, $config);

        $method = $reflection->getMethod($methodName);
        $result = $method->invoke($protocol, ...$arguments);

        return is_array($result) ? $result : $configProperty->getValue($protocol);
    }
}
