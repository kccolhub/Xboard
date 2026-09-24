<?php

namespace Tests\Unit\Protocols;

use App\Protocols\General;
use App\Protocols\Shadowrocket;
use App\Http\Requests\Admin\ServerSave;
use Illuminate\Container\Container;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Response;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class HysteriaCertificateTest extends TestCase
{
    private static string $certificate;
    private static string $privateKey;
    private static string $fingerprint;
    private static string $secondCertificate;

    public static function setUpBeforeClass(): void
    {
        [self::$certificate, self::$privateKey] = self::makeCertificate('node.example.com');
        [self::$secondCertificate] = self::makeCertificate('other.example.com');
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', self::$certificate), true);
        self::$fingerprint = hash('sha256', $der);
    }

    private static function makeCertificate(string $domain): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => $domain], $key, ['digest_alg' => 'sha256']);
        $certificate = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        openssl_x509_export($certificate, $pem);
        openssl_pkey_export($key, $keyPem);
        return [$pem, $keyPem];
    }

    public static function generators(): array
    {
        return ['general' => [General::class], 'shadowrocket' => [Shadowrocket::class]];
    }

    private function server(): array
    {
        return [
            'name' => 'hysteria2-internal-3',
            'type' => 'hysteria',
            'host' => '192.0.2.10',
            'port' => 57683,
            'password' => 'example-auth',
            'protocol_settings' => [
                'version' => 2,
                'bandwidth' => ['up' => 100, 'down' => 200],
                'tls' => ['allow_insecure' => true],
                'obfs' => ['open' => true, 'type' => 'salamander', 'password' => 'obfs-secret'],
            ],
            'cert_config' => [
                'mode' => 'content',
                'cert_content' => self::$certificate,
                'key_content' => self::$privateKey,
            ],
        ];
    }

    private function parameters(string $link): array
    {
        parse_str(parse_url(trim($link), PHP_URL_QUERY), $parameters);
        return $parameters;
    }

    #[DataProvider('generators')]
    public function test_content_certificate_is_pinned_in_the_requested_link_format(string $generator): void
    {
        $link = $generator::buildHysteria('example-auth', $this->server());
        $params = $this->parameters($link);
        $this->assertStringStartsWith('hysteria2://example-auth@192.0.2.10:57683?', $link);
        $this->assertStringEndsWith('#hysteria2-internal-3' . "\r\n", $link);
        $this->assertSame(self::$fingerprint, $params['pinSHA256']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $params['pinSHA256']);
        foreach (['upmbps' => '100', 'downmbps' => '200', 'security' => 'tls', 'insecure' => '1',
            'disable_sni' => '1', 'obfs' => 'salamander', 'obfs-password' => 'obfs-secret', 'fastopen' => '0'] as $key => $value) {
            $this->assertSame($value, $params[$key], $key);
        }
        $this->assertStringNotContainsString('BEGIN', $link);
        $this->assertStringNotContainsString(self::$privateKey, $link);
    }

    #[DataProvider('generators')]
    public function test_explicit_sni_and_certificate_verification_setting_are_preserved(string $generator): void
    {
        $server = $this->server();
        $server['protocol_settings']['tls'] = ['server_name' => 'node.example.com', 'allow_insecure' => false];
        $params = $this->parameters($generator::buildHysteria('example-auth', $server));
        $this->assertSame('node.example.com', $params[$generator === General::class ? 'sni' : 'peer']);
        $this->assertSame('0', $params['disable_sni']);
        $this->assertSame('0', $params['insecure']);
        $this->assertSame(self::$fingerprint, $params['pinSHA256']);
    }

    #[DataProvider('generators')]
    public function test_cert_mode_alias_chain_and_crlf_pin_the_first_certificate(string $generator): void
    {
        $server = $this->server();
        unset($server['cert_config']['mode']);
        $server['cert_config']['cert_mode'] = 'content';
        $server['cert_config']['cert_content'] = str_replace("\n", "\r\n", self::$certificate . self::$secondCertificate);
        $params = $this->parameters($generator::buildHysteria('example-auth', $server));
        $this->assertSame(self::$fingerprint, $params['pinSHA256']);
    }

    #[DataProvider('generators')]
    public function test_rotating_the_content_certificate_changes_the_subscription_pin(string $generator): void
    {
        $server = $this->server();
        $before = $this->parameters($generator::buildHysteria('example-auth', $server));
        $server['cert_config']['cert_content'] = self::$secondCertificate;
        $after = $this->parameters($generator::buildHysteria('example-auth', $server));
        $this->assertNotSame($before['pinSHA256'], $after['pinSHA256']);
        $this->assertSame(openssl_x509_fingerprint(self::$secondCertificate, 'sha256'), $after['pinSHA256']);
    }

    #[DataProvider('generators')]
    public function test_other_certificate_modes_do_not_pin_stale_content(string $generator): void
    {
        foreach (['self', 'http', 'dns', 'file', 'none', ''] as $mode) {
            $server = $this->server();
            $server['cert_config']['mode'] = $mode;
            $params = $this->parameters($generator::buildHysteria('example-auth', $server));
            $this->assertArrayNotHasKey('pinSHA256', $params, $mode);
            $this->assertArrayNotHasKey('disable_sni', $params, $mode);
        }
    }

    #[DataProvider('generators')]
    public function test_invalid_content_does_not_silently_generate_an_unpinned_link(string $generator): void
    {
        foreach (['', 'not a certificate', '-----BEGIN CERTIFICATE-----' . "\nAAAA\n" . '-----END CERTIFICATE-----', 'file:///etc/passwd', self::$privateKey] as $content) {
            $server = $this->server();
            $server['cert_config']['cert_content'] = $content;
            try {
                $generator::buildHysteria('example-auth', $server);
                $this->fail('Invalid certificate content must be rejected.');
            } catch (InvalidArgumentException $e) {
                $this->assertSame('Content certificate mode requires a valid PEM certificate.', $e->getMessage());
            }
        }
    }

    #[DataProvider('generators')]
    public function test_hysteria_one_is_unchanged(string $generator): void
    {
        $server = $this->server();
        $server['protocol_settings']['version'] = 1;
        $server['cert_config']['cert_content'] = 'not used by hysteria one';
        $link = $generator::buildHysteria('example-auth', $server);
        $this->assertStringStartsWith('hysteria://', $link);
        $this->assertArrayNotHasKey('pinSHA256', $this->parameters($link));
    }

    public function test_admin_save_accepts_valid_content_and_rejects_invalid_certificates(): void
    {
        $factory = new Factory(new Translator(new ArrayLoader(), 'en'));
        foreach ([self::$certificate, '', 'not a certificate', ['invalid shape']] as $content) {
            $server = $this->server();
            $server['server_port'] = $server['port'];
            $server['rate'] = 1;
            $server['cert_config']['cert_content'] = $content;
            $request = ServerSave::create('/', 'POST', $server);
            $validator = $factory->make($server, $request->rules());
            $request->withValidator($validator);
            $this->assertSame($content === self::$certificate, $validator->passes());
            if ($content !== self::$certificate) {
                $this->assertArrayHasKey('cert_config.cert_content', $validator->errors()->toArray());
            }
        }
    }

    #[DataProvider('generators')]
    public function test_no_certificate_config_ipv6_and_port_hopping_still_work(string $generator): void
    {
        $server = $this->server();
        unset($server['cert_config']);
        $server['host'] = '2001:db8::1';
        $server['ports'] = '57683-57690';
        $server['protocol_settings']['bandwidth'] = ['up' => 0, 'down' => -1];
        $link = $generator::buildHysteria('example-auth', $server);
        $params = $this->parameters($link);
        $this->assertStringContainsString('@[2001:db8::1]:57683?', $link);
        $this->assertSame('57683-57690', $params['mport']);
        foreach (['pinSHA256', 'upmbps', 'downmbps'] as $parameter) {
            $this->assertArrayNotHasKey($parameter, $params);
        }
    }

    #[DataProvider('generators')]
    public function test_base64_subscription_contains_the_pin_and_no_certificate_material(string $generator): void
    {
        $previousContainer = Container::getInstance();
        $container = new Container();
        $responses = $this->createMock(ResponseFactory::class);
        $responses->method('make')->willReturnCallback(fn($body, $status = 200, $headers = []) => new Response($body, $status, $headers));
        $container->instance(ResponseFactory::class, $responses);
        Container::setInstance($container);
        try {
            // Exercise the real subscription encoder without unrelated DB/plugin setup.
            $reflection = new ReflectionClass($generator);
            $protocol = $reflection->newInstanceWithoutConstructor();
            $reflection->getProperty('servers')->setValue($protocol, [$this->server()]);
            $reflection->getProperty('user')->setValue($protocol, ['u' => 0, 'd' => 0, 'transfer_enable' => 1024, 'expired_at' => null]);
            $decoded = base64_decode($protocol->handle()->getContent(), true);
            $links = array_values(array_filter(explode("\r\n", $decoded), fn($line) => str_starts_with($line, 'hysteria2://')));
            $this->assertCount(1, $links);
            $this->assertSame(self::$fingerprint, $this->parameters($links[0])['pinSHA256']);
            $this->assertStringNotContainsString('BEGIN', $decoded);
            $this->assertStringNotContainsString(self::$privateKey, $decoded);
        } finally {
            Container::setInstance($previousContainer);
        }
    }
}
