<?php

return [
    'binary' => env('NODE_PROBE_SING_BOX', '/usr/local/bin/sing-box'),
    'version' => '1.14.0',
    'ca_bundle' => env('NODE_PROBE_CA_BUNDLE'),
    // Not user-supplied: avoid turning this endpoint into an arbitrary HTTP proxy.
    'target' => 'https://www.gstatic.com/generate_204',
    'expected_status' => 204,
    'timeout' => 12,
    'fresh_seconds' => 300,
    'retain_seconds' => 86400,
];
