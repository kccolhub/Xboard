<?php

namespace Tests\Unit\Protocols;

use App\Http\Controllers\V2\Admin\Server\ManageController;
use App\Protocols\General;
use App\Utils\Certificate;
use Illuminate\Container\Container;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class CertificateGeneratorTest extends TestCase
{
    public static function names(): array
    {
        return [
            'domain' => ['Node.Example.com', 'DNS:node.example.com'],
            'ipv4' => ['192.0.2.1', 'IP Address:192.0.2.1'],
            'ipv6' => ['2001:db8::1', 'IP Address:2001:DB8:0:0:0:0:0:1'],
            'long domain' => [str_repeat('a', 60) . '.example.com', 'DNS:' . str_repeat('a', 60) . '.example.com'],
        ];
    }

    #[DataProvider('names')]
    public function test_generated_certificate_has_the_requested_san_and_matching_private_key(string $name, string $san): void
    {
        $result = Certificate::generate($name);
        $certificate = openssl_x509_parse($result['cert_content']);
        $this->assertSame(strtolower($name), $result['domain']);
        $this->assertSame($san, $certificate['extensions']['subjectAltName']);
        $this->assertSame('CA:FALSE', $certificate['extensions']['basicConstraints']);
        $this->assertStringContainsString('TLS Web Server Authentication', $certificate['extensions']['extendedKeyUsage']);
        $this->assertTrue(openssl_x509_check_private_key($result['cert_content'], $result['key_content']));
        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_private($result['key_content']));
        $this->assertSame(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
        $this->assertSame('prime256v1', $keyDetails['ec']['curve_name']);
        $this->assertSame(256, $keyDetails['bits']);
        $this->assertSame(1, openssl_x509_verify($result['cert_content'], openssl_pkey_get_public($result['cert_content'])));
        $this->assertGreaterThan(time() + 3649 * 86400, $certificate['validTo_time_t']);
        $this->assertSame(openssl_x509_fingerprint($result['cert_content'], 'sha256'), $result['pinSHA256']);
    }

    public function test_generated_content_is_directly_usable_by_the_subscription_generator(): void
    {
        $content = Certificate::generate('node.example.com');
        $server = ['name' => 'generated', 'host' => '192.0.2.1', 'port' => 443,
            'protocol_settings' => ['version' => 2, 'tls' => ['allow_insecure' => true]],
            'cert_config' => ['cert_mode' => 'content'] + $content];
        $link = General::buildHysteria('example-auth', $server);
        parse_str(parse_url(trim($link), PHP_URL_QUERY), $params);
        $this->assertSame($content['pinSHA256'], $params['pinSHA256']);
        $this->assertStringNotContainsString('BEGIN', $link);
        $this->assertStringNotContainsString($content['key_content'], $link);
        $this->assertNotSame($content['pinSHA256'], Certificate::generate('node.example.com')['pinSHA256']);
    }

    public static function invalidNames(): array
    {
        return array_map(fn($value) => [$value], ['', 'https://example.com', '../cert', 'example.com:443',
            "example.com\nsubjectAltName=DNS:other.com", '*.example.com', str_repeat('a', 64) . '.com',
            str_repeat('a.', 130) . 'com', 'a b.com']);
    }

    #[DataProvider('invalidNames')]
    public function test_invalid_names_cannot_inject_openssl_configuration(string $name): void
    {
        $this->expectException(InvalidArgumentException::class);
        Certificate::generate($name);
    }

    public function test_admin_endpoint_returns_autofill_fields_without_caching_the_private_key(): void
    {
        $previous = Container::getInstance();
        $container = new Container();
        $responses = $this->createMock(ResponseFactory::class);
        $responses->method('json')->willReturnCallback(fn($data, $status = 200, $headers = []) => new JsonResponse($data, $status, $headers));
        $container->instance(ResponseFactory::class, $responses);
        Container::setInstance($container);
        try {
            $request = new class extends Request {
                public function validate(array $rules): array
                {
                    return (new Factory(new Translator(new ArrayLoader(), 'en')))->make($this->all(), $rules)->validate();
                }
            };
            $request->replace(['domain' => 'node.example.com']);
            $response = (new ManageController())->generateCertificate($request);
            $this->assertSame(200, $response->status());
            $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
            $data = $response->getData(true)['data'];
            $this->assertTrue(openssl_x509_check_private_key($data['cert_content'], $data['key_content']));
            $this->assertSame('node.example.com', $data['domain']);
        } finally {
            Container::setInstance($previous);
        }
    }
}
