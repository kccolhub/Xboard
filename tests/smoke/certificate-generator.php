<?php

// Run in the production image: no PHPUnit/dev dependencies or real node data.
require __DIR__ . '/../../app/Utils/Certificate.php';

use App\Utils\Certificate;

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
} finally {
    restore_error_handler();
}
