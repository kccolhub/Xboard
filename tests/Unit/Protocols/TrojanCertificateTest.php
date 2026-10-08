<?php

namespace Tests\Unit\Protocols;

use App\Http\Requests\Admin\ServerSave;
use App\Protocols\General;
use App\Utils\Certificate;
use Illuminate\Container\Container;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Response;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory;
use Illuminate\Validation\Validator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class TrojanCertificateTest extends TestCase
{
    private static array $certificate;
    private static array $otherCertificate;

    public static function setUpBeforeClass(): void
    {
        self::$certificate = Certificate::generate('node.example.com');
        self::$otherCertificate = Certificate::generate('other.example.com');
    }

    private function server(): array
    {
        return [
            'name' => 'trojan-content', 'type' => 'trojan',
            'host' => '192.0.2.10', 'port' => 37165, 'server_port' => 37165,
            'rate' => 1, 'password' => 'example-auth',
            'protocol_settings' => [
                'tls' => 1, 'network' => 'tcp',
                'tls_settings' => ['server_name' => 'node.example.com', 'allow_insecure' => true],
                'utls' => ['enabled' => true, 'fingerprint' => 'chrome'],
            ],
            'cert_config' => ['cert_mode' => 'content'] + self::$certificate,
        ];
    }

    private function parameters(array $server): array
    {
        parse_str(parse_url(trim(General::buildTrojan('example-auth', $server)), PHP_URL_QUERY), $parameters);
        return $parameters;
    }

    private function validator(array $server): Validator
    {
        $request = ServerSave::create('/', 'POST', $server);
        $factory = new Factory(new Translator(new ArrayLoader(), 'en'));
        $validator = $factory->make($server, $request->rules());
        $request->withValidator($validator);
        return $validator;
    }

    public static function contentOptions(): array
    {
        return [
            'current mode, insecure' => ['cert_mode', true],
            'current mode, verified' => ['cert_mode', false],
            'legacy mode, insecure' => ['mode', true],
            'legacy mode, verified' => ['mode', false],
        ];
    }

    #[DataProvider('contentOptions')]
    public function test_content_certificate_exports_the_leaf_pin_and_preserves_link_settings(string $modeField, bool $insecure): void
    {
        $server = $this->server();
        $server['cert_config'] = [$modeField => 'content'] + self::$certificate;
        $server['protocol_settings']['tls_settings']['allow_insecure'] = $insecure;
        $server['protocol_settings']['network'] = 'ws';
        $server['protocol_settings']['network_settings'] = ['path' => '/proxy', 'headers' => ['Host' => 'edge.example.com']];
        $params = $this->parameters($server);
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', self::$certificate['cert_content']), true);
        $this->assertSame(hash('sha256', $der), $params['pcs']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $params['pcs']);
        foreach (['allowInsecure' => $insecure ? '1' : '0', 'sni' => 'node.example.com',
            'peer' => 'node.example.com', 'fp' => 'chrome', 'type' => 'ws',
            'path' => '/proxy', 'host' => 'edge.example.com'] as $key => $value) {
            $this->assertSame($value, $params[$key], $key);
        }
        $link = General::buildTrojan('example-auth', $server);
        $this->assertStringStartsWith('trojan://example-auth@192.0.2.10:37165?', $link);
        $this->assertStringEndsWith("#trojan-content\r\n", $link);
        $this->assertStringNotContainsString('BEGIN', $link);
        $this->assertStringNotContainsString(self::$certificate['key_content'], $link);
    }

    public function test_certificate_chain_pins_the_first_leaf_and_rotation_updates_the_pin(): void
    {
        $server = $this->server();
        $server['cert_config']['cert_content'] = str_replace("\n", "\r\n", self::$certificate['cert_content'] . self::$otherCertificate['cert_content']);
        $this->assertSame(self::$certificate['pinSHA256'], $this->parameters($server)['pcs']);
        $server['cert_config']['cert_content'] = self::$otherCertificate['cert_content'];
        $this->assertSame(self::$otherCertificate['pinSHA256'], $this->parameters($server)['pcs']);
        $this->assertNotSame(self::$certificate['pinSHA256'], $this->parameters($server)['pcs']);
    }

    public function test_other_certificate_modes_do_not_export_stale_content(): void
    {
        foreach (['self', 'http', 'dns', 'file', 'none', ''] as $mode) {
            $server = $this->server();
            $server['cert_config']['cert_mode'] = $mode;
            $server['cert_config']['cert_content'] = 'unused stale certificate';
            $this->assertArrayNotHasKey('pcs', $this->parameters($server), $mode);
            $this->assertTrue($this->validator($server)->passes(), $mode);
        }
        unset($server['cert_config']);
        $server['host'] = '2001:db8::1';
        $this->assertArrayNotHasKey('pcs', $this->parameters($server));
        $this->assertStringContainsString('@[2001:db8::1]:37165?', General::buildTrojan('example-auth', $server));
    }

    public function test_reality_ignores_unused_content_certificates(): void
    {
        $server = $this->server();
        $server['protocol_settings']['tls'] = 2;
        $server['protocol_settings']['reality_settings'] = [
            'public_key' => 'example-public-key', 'short_id' => 'abcd', 'server_name' => 'target.example.com',
        ];
        $server['cert_config']['cert_content'] = 'unused by Reality';
        $server['cert_config']['key_content'] = 'unused by Reality';
        $params = $this->parameters($server);
        $this->assertArrayNotHasKey('pcs', $params);
        $this->assertArrayNotHasKey('allowInsecure', $params);
        $this->assertSame('reality', $params['security']);
        $this->assertSame('example-public-key', $params['pbk']);
        $this->assertSame('target.example.com', $params['sni']);
        $this->assertTrue($this->validator($server)->passes());
    }

    public static function invalidCertificates(): array
    {
        return [
            'empty' => [''], 'invalid text' => ['not a certificate'],
            'invalid DER' => ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"],
            'file reference' => ['file:///example/cert.pem'], 'invalid shape' => [['invalid']],
        ];
    }

    #[DataProvider('invalidCertificates')]
    public function test_invalid_content_is_rejected_on_save_and_cannot_export_an_unpinned_link(mixed $content): void
    {
        $server = $this->server();
        $server['cert_config']['cert_content'] = $content;
        $validator = $this->validator($server);
        $this->assertFalse($validator->passes());
        $this->assertArrayHasKey('cert_config.cert_content', $validator->errors()->toArray());
        $this->expectException(InvalidArgumentException::class);
        General::buildTrojan('example-auth', $server);
    }

    public function test_save_rejects_missing_invalid_or_mismatched_private_keys(): void
    {
        foreach ([null, '', 'invalid', ['invalid'], 'file:///example/key.pem', self::$otherCertificate['key_content']] as $key) {
            $server = $this->server();
            $server['cert_config']['key_content'] = $key;
            $validator = $this->validator($server);
            $this->assertFalse($validator->passes());
            $this->assertArrayHasKey('cert_config.key_content', $validator->errors()->toArray());
        }
    }

    public function test_legacy_trojan_without_an_explicit_tls_mode_is_validated_and_pinned(): void
    {
        $server = $this->server();
        unset($server['protocol_settings']['tls']);
        $this->assertTrue($this->validator($server)->passes());
        $this->assertSame(self::$certificate['pinSHA256'], $this->parameters($server)['pcs']);
        $server['cert_config']['key_content'] = self::$otherCertificate['key_content'];
        $this->assertFalse($this->validator($server)->passes());
    }

    public function test_saved_certificate_is_preserved_and_exported_in_the_base64_subscription(): void
    {
        $server = $this->server();
        $saved = $this->validator($server)->validated();
        $this->assertSame($server['cert_config'], $saved['cert_config']);
        $saved['password'] = $server['password'];
        $previous = Container::getInstance();
        $container = new Container();
        $responses = $this->createMock(ResponseFactory::class);
        $responses->method('make')->willReturnCallback(fn($body, $status = 200, $headers = []) => new Response($body, $status, $headers));
        $container->instance(ResponseFactory::class, $responses);
        Container::setInstance($container);
        try {
            $reflection = new ReflectionClass(General::class);
            $protocol = $reflection->newInstanceWithoutConstructor();
            $reflection->getProperty('servers')->setValue($protocol, [$saved]);
            $reflection->getProperty('user')->setValue($protocol, ['u' => 0, 'd' => 0, 'transfer_enable' => 1024, 'expired_at' => null]);
            $decoded = base64_decode($protocol->handle()->getContent(), true);
            $links = array_values(array_filter(explode("\r\n", $decoded)));
            $this->assertCount(1, $links);
            parse_str(parse_url($links[0], PHP_URL_QUERY), $params);
            $this->assertSame(self::$certificate['pinSHA256'], $params['pcs']);
            $this->assertStringNotContainsString('BEGIN', $decoded);
            $this->assertStringNotContainsString(self::$certificate['key_content'], $decoded);
        } finally {
            Container::setInstance($previous);
        }
    }
}
