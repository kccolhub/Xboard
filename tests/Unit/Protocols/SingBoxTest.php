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

    private function normalizeDnsDetours(array $config): array
    {
        $reflection = new ReflectionClass(SingBox::class);
        /** @var SingBox $protocol */
        $protocol = $reflection->newInstanceWithoutConstructor();

        $configProperty = $reflection->getProperty('config');
        $configProperty->setValue($protocol, $config);

        $method = $reflection->getMethod('removeEmptyDirectDnsDetours');
        $method->invoke($protocol);

        return $configProperty->getValue($protocol);
    }
}
