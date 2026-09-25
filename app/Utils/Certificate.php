<?php

namespace App\Utils;

use InvalidArgumentException;
use RuntimeException;

class Certificate
{
    /** Generate a fresh self-signed leaf certificate without persisting a node. */
    public static function generate(string $domain): array
    {
        $domain = strtolower(trim($domain));
        $isIp = filter_var($domain, FILTER_VALIDATE_IP) !== false;
        if ($domain === '' || strlen($domain) > 253
            || (!$isIp && !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME))) {
            throw new InvalidArgumentException('请输入有效的证书域名或 IP 地址。');
        }

        // The validated name cannot inject OpenSSL configuration directives.
        $san = ($isIp ? 'IP:' : 'DNS:') . $domain;
        // PHP 8.2 validates default_bits before selecting the EC curve, even
        // though the EC key size is determined by prime256v1 below.
        $configuration = "[req]\ndefault_bits=2048\ndistinguished_name=dn\n[dn]\n[v3_leaf]\n"
            . "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            . "extendedKeyUsage=serverAuth\nsubjectAltName={$san}\n";
        $path = tempnam(sys_get_temp_dir(), 'xboard-cert-');
        if ($path === false) {
            throw new RuntimeException('无法创建证书生成配置。');
        }
        try {
            if (file_put_contents($path, $configuration) === false) {
                throw new RuntimeException('无法创建证书生成配置。');
            }
            $options = ['config' => $path, 'digest_alg' => 'sha256'];
            $key = openssl_pkey_new($options + [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => 'prime256v1',
            ]);
            if ($key === false) {
                throw new RuntimeException('无法生成证书私钥。');
            }
            // Common names have a 64-byte limit; SAN retains the complete name.
            $csr = openssl_csr_new(['commonName' => strlen($domain) <= 64 ? $domain : 'Xboard Node'], $key,
                $options + ['req_extensions' => 'v3_leaf']);
            $cert = $csr === false ? false : openssl_csr_sign($csr, null, $key, 3650,
                $options + ['x509_extensions' => 'v3_leaf'], random_int(1, PHP_INT_MAX));
            if ($cert === false || !openssl_x509_export($cert, $certificate)
                || !openssl_pkey_export($key, $privateKey, null, $options)) {
                throw new RuntimeException('无法生成自签名证书。');
            }
            return [
                'domain' => $domain,
                'cert_content' => $certificate,
                'key_content' => $privateKey,
                'pinSHA256' => openssl_x509_fingerprint($cert, 'sha256'),
            ];
        } finally {
            unlink($path);
        }
    }

    /**
     * Pin the leaf certificate pushed to a node, never its public key or PEM text.
     * Other certificate modes need node-side certificate discovery instead.
     */
    public static function contentFingerprint(array $server): ?string
    {
        $pem = self::contentPem($server);
        if ($pem === null) return null;
        $fingerprint = openssl_x509_fingerprint($pem, 'sha256');
        if ($fingerprint === false) {
            throw new InvalidArgumentException('Content certificate mode requires a valid PEM certificate.');
        }
        return strtolower($fingerprint);
    }

    /** Extract only the public leaf certificate pushed by the panel, never its key. */
    public static function contentPem(array $server): ?string
    {
        $config = $server['cert_config'] ?? [];
        $mode = $config['cert_mode'] ?? '';
        if ($mode === '') {
            $mode = $config['mode'] ?? '';
        }
        if (strtolower(trim($mode)) !== 'content') {
            return null;
        }

        $pem = $config['cert_content'] ?? '';
        // Extract only the first certificate from a PEM chain. In particular,
        // never pass a file:// reference or private key to the OpenSSL loader.
        if (!is_string($pem) || !preg_match(
            '/-----BEGIN CERTIFICATE-----[A-Za-z0-9+\/=\s]+-----END CERTIFICATE-----/',
            $pem,
            $matches
        )) {
            throw new InvalidArgumentException('Content certificate mode requires a valid PEM certificate.');
        }

        if (@openssl_x509_read($matches[0]) === false) {
            throw new InvalidArgumentException('Content certificate mode requires a valid PEM certificate.');
        }
        return trim($matches[0]);
    }
}
