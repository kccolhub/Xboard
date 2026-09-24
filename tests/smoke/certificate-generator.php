<?php

// Run in the production image: no PHPUnit/dev dependencies or real node data.
require __DIR__ . '/../../vendor/autoload.php';

use App\Http\Requests\Admin\ServerSave;
use App\Utils\Certificate;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory;

// Match Laravel's warning-to-exception behavior on PHP 8.2.
set_error_handler(static function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

try {
    foreach (['node.example.com', '192.0.2.1', '2001:db8::1'] as $name) {
        $result = Certificate::generate($name);
        $key = openssl_pkey_get_private($result['key_content']);
        $details = openssl_pkey_get_details($key);
        $certificate = openssl_x509_read($result['cert_content']);
        if ($details['type'] !== OPENSSL_KEYTYPE_EC || $details['bits'] !== 256
            || $details['ec']['curve_name'] !== 'prime256v1'
            || !openssl_x509_check_private_key($certificate, $key)
            || openssl_x509_verify($certificate, openssl_pkey_get_public($certificate)) !== 1
            || Certificate::contentFingerprint(['cert_config' => ['cert_mode' => 'content'] + $result]) !== $result['pinSHA256']) {
            throw new RuntimeException('Generated certificate/key/pin verification failed.');
        }
    }
    fwrite(STDOUT, 'Certificate generation smoke passed on PHP ' . PHP_VERSION . PHP_EOL);
    $server = ['name' => 'certificate-smoke', 'type' => 'hysteria', 'host' => '192.0.2.1',
        'port' => 443, 'server_port' => 443, 'rate' => 1, 'protocol_settings' => ['version' => 2],
        'cert_config' => ['cert_mode' => 'content'] + $result];
    $request = ServerSave::create('/', 'POST', $server);
    $factory = new Factory(new Translator(new ArrayLoader(), 'en'));
    $validator = $factory->make($server, $request->rules());
    $request->withValidator($validator);
    if ($validator->validated()['cert_config'] !== $server['cert_config']) {
        throw new RuntimeException('Certificate save stripped configuration fields.');
    }
    fwrite(STDOUT, 'Certificate save preserves matching private key and domain' . PHP_EOL);
} finally {
    restore_error_handler();
}
