<?php
namespace App\Protocols;

use App\Utils\Helper;
use Illuminate\Support\Arr;
use App\Support\AbstractProtocol;
use App\Models\Server;
use Log;

class SingBox extends AbstractProtocol
{
    public $flags = ['sing-box', 'hiddify', 'sfa', 'sfi', 'sfm'];
    public $allowedProtocols = [
        Server::TYPE_SHADOWSOCKS,
        Server::TYPE_TROJAN,
        Server::TYPE_VMESS,
        Server::TYPE_VLESS,
        Server::TYPE_HYSTERIA,
        Server::TYPE_TUIC,
        Server::TYPE_ANYTLS,
        Server::TYPE_SOCKS,
        Server::TYPE_HTTP,
    ];
    private $config;
    const CUSTOM_TEMPLATE_FILE = 'resources/rules/custom.sing-box.json';
    const DEFAULT_TEMPLATE_FILE = 'resources/rules/default.sing-box.json';

    /**
     * 多客户端协议支持配置
     */
    protected $protocolRequirements = [
        'sing-box' => [
            'vless' => [
                'base_version' => '1.5.0',
                'protocol_settings.flow' => [
                    'xtls-rprx-vision' => '1.5.0'
                ],
                'protocol_settings.tls' => [
                    '2' => '1.6.0' // Reality
                ],
                'protocol_settings.tls_settings.ech.enabled' => [
                    1 => '1.5.0'
                ],
                'protocol_settings.network' => [
                    'xhttp' => '9999.0.0'
                ]
            ],
            'vmess' => [
                'protocol_settings.tls_settings.ech.enabled' => [
                    1 => '1.5.0'
                ],
                'protocol_settings.network' => [
                    'xhttp' => '9999.0.0'
                ]
            ],
            'trojan' => [
                'protocol_settings.tls_settings.ech.enabled' => [
                    1 => '1.5.0'
                ],
                'protocol_settings.network' => [
                    'xhttp' => '9999.0.0'
                ]
            ],
            'hysteria' => [
                'base_version' => '1.5.0',
                'protocol_settings.version' => [
                    '2' => '1.5.0' // Hysteria 2
                ],
                'protocol_settings.tls.ech.enabled' => [
                    1 => '1.5.0'
                ]
            ],
            'tuic' => [
                'base_version' => '1.5.0',
                'protocol_settings.tls.ech.enabled' => [
                    1 => '1.5.0'
                ]
            ],
            'ssh' => [
                'base_version' => '1.8.0'
            ],
            'juicity' => [
                'base_version' => '1.7.0'
            ],
            'wireguard' => [
                'base_version' => '1.5.0'
            ],
            'anytls' => [
                'base_version' => '1.12.0',
                'protocol_settings.tls.ech.enabled' => [
                    1 => '1.12.0'
                ]
            ],
            'socks' => [
                'protocol_settings.tls_settings.ech.enabled' => [
                    1 => '1.5.0'
                ]
            ],
            'naive' => [
                'protocol_settings.tls_settings.ech.enabled' => [
                    1 => '1.5.0'
                ]
            ],
            'http' => [
                'protocol_settings.tls_settings.ech.enabled' => [
                    1 => '1.5.0'
                ]
            ],
        ]
    ];

    /** Build just one proxy, without template rules, selectors or direct fallback. */
    public function buildProbeOutbound(): array
    {
        if (count($this->servers) !== 1) {
            throw new \InvalidArgumentException('Node is not supported by this sing-box version');
        }
        $server = array_values($this->servers)[0];
        $method = match ($server['type']) {
            Server::TYPE_SHADOWSOCKS => 'buildShadowsocks',
            Server::TYPE_TROJAN => 'buildTrojan',
            Server::TYPE_VMESS => 'buildVmess',
            Server::TYPE_VLESS => 'buildVless',
            Server::TYPE_HYSTERIA => 'buildHysteria',
            Server::TYPE_TUIC => 'buildTuic',
            Server::TYPE_ANYTLS => 'buildAnyTLS',
            Server::TYPE_SOCKS => 'buildSocks',
            Server::TYPE_HTTP => 'buildHttp',
            default => throw new \InvalidArgumentException('Unsupported node protocol'),
        };
        $password = $server['type'] === Server::TYPE_SHADOWSOCKS ? $server['password'] : $this->user['uuid'];
        $outbound = $this->$method($password, $server);
        $outbound['tag'] = 'probe';
        return $outbound;
    }

    public function handle()
    {
        $appName = admin_setting('app_name', 'XBoard');
        $this->config = $this->loadConfig();
        $this->buildOutbounds();
        $this->buildRule();
        $this->adaptConfigForVersion();
        $user = $this->user;

        return response()
            ->json($this->config)
            ->header('profile-title', 'base64:' . base64_encode($appName))
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}")
            ->header('profile-update-interval', '24');
    }

    protected function loadConfig()
    {
        $jsonData = subscribe_template('singbox');
        $config = is_array($jsonData) ? $jsonData : json_decode($jsonData, true);

        if (!is_array($config)) {
            return $config;
        }

        return $this->forceIpv4Only($config);
    }

    /** Ensure generated subscriptions never resolve or route through IPv6. */
    private function forceIpv4Only(array $config): array
    {
        $config['dns'] ??= [];
        $config['route'] ??= [];
        $config['dns']['strategy'] = 'ipv4_only';

        if (isset($config['dns']['rules']) && is_array($config['dns']['rules'])) {
            foreach ($config['dns']['rules'] as &$rule) {
                if (($rule['action'] ?? null) === 'route' || isset($rule['server'])) {
                    $rule['strategy'] = 'ipv4_only';
                }
            }
            unset($rule);
        }

        $config['route']['default_domain_resolver'] ??= ['server' => 'local'];
        $config['route']['default_domain_resolver']['strategy'] = 'ipv4_only';

        $legacyResolveInbounds = [];
        if (isset($config['inbounds']) && is_array($config['inbounds'])) {
            foreach ($config['inbounds'] as &$inbound) {
            if (($inbound['type'] ?? null) === 'tun' && isset($inbound['address'])) {
                $inbound['address'] = array_values(array_filter(
                    (array) $inbound['address'],
                    fn ($address) => !str_contains((string) $address, ':')
                ));
            }
            if (array_key_exists('domain_strategy', $inbound)) {
                $inbound['domain_strategy'] = 'ipv4_only';
                if (isset($inbound['tag'])) {
                    $legacyResolveInbounds[$inbound['tag']] = true;
                }
            }
            }
            unset($inbound);
        }

        // Keep any template-provided per-outbound resolver preferences from
        // falling back to IPv6.  We only touch the field when it already
        // exists because older sing-box cores reject unknown outbound fields.
        if (isset($config['outbounds']) && is_array($config['outbounds'])) {
            foreach ($config['outbounds'] as &$outbound) {
            if (array_key_exists('domain_strategy', $outbound)) {
                $outbound['domain_strategy'] = 'ipv4_only';
            }
            }
            unset($outbound);
        }

        $resolveInbounds = [];
        if (isset($config['route']['rules']) && is_array($config['route']['rules'])) {
            foreach ($config['route']['rules'] as &$rule) {
                if (($rule['action'] ?? null) !== 'resolve') {
                    continue;
                }

                $rule['strategy'] = 'ipv4_only';
                $targets = $rule['inbound'] ?? [];
                $targets = is_array($targets) ? $targets : [$targets];
                if ($targets === []) {
                    foreach ($config['inbounds'] ?? [] as $inbound) {
                        if (isset($inbound['tag'])) {
                            $resolveInbounds[$inbound['tag']] = true;
                        }
                    }
                }
                foreach ($targets as $tag) {
                    $resolveInbounds[$tag] = true;
                }
            }
            unset($rule);
        }

        foreach ($config['inbounds'] ?? [] as $inbound) {
            $tag = $inbound['tag'] ?? null;
            if ($tag === null || isset($resolveInbounds[$tag]) || isset($legacyResolveInbounds[$tag])) {
                continue;
            }

            array_unshift($config['route']['rules'], [
                'inbound' => $tag,
                'action' => 'resolve',
                'strategy' => 'ipv4_only',
            ]);
            $resolveInbounds[$tag] = true;
        }

        return $config;
    }

    protected function buildOutbounds()
    {
        $outbounds = $this->config['outbounds'];
        $proxies = [];
        foreach ($this->servers as $item) {
            $protocol_settings = $item['protocol_settings'];
            if ($item['type'] === Server::TYPE_SHADOWSOCKS) {
                $ssConfig = $this->buildShadowsocks($item['password'], $item);
                $proxies[] = $ssConfig;
            }
            if ($item['type'] === Server::TYPE_TROJAN) {
                $trojanConfig = $this->buildTrojan($this->user['uuid'], $item);
                $proxies[] = $trojanConfig;
            }
            if ($item['type'] === Server::TYPE_VMESS) {
                $vmessConfig = $this->buildVmess($this->user['uuid'], $item);
                $proxies[] = $vmessConfig;
            }
            if (
                $item['type'] === Server::TYPE_VLESS
                && in_array(data_get($protocol_settings, 'network'), ['tcp', 'ws', 'grpc', 'http', 'quic', 'httpupgrade'])
            ) {
                $vlessConfig = $this->buildVless($this->user['uuid'], $item);
                $proxies[] = $vlessConfig;
            }
            if ($item['type'] === Server::TYPE_HYSTERIA) {
                $hysteriaConfig = $this->buildHysteria($this->user['uuid'], $item);
                $proxies[] = $hysteriaConfig;
            }
            if ($item['type'] === Server::TYPE_TUIC) {
                $tuicConfig = $this->buildTuic($this->user['uuid'], $item);
                $proxies[] = $tuicConfig;
            }
            if ($item['type'] === Server::TYPE_ANYTLS) {
                $anytlsConfig = $this->buildAnyTLS($this->user['uuid'], $item);
                $proxies[] = $anytlsConfig;
            }
            if ($item['type'] === Server::TYPE_SOCKS) {
                $socksConfig = $this->buildSocks($this->user['uuid'], $item);
                $proxies[] = $socksConfig;
            }
            if ($item['type'] === Server::TYPE_HTTP) {
                $httpConfig = $this->buildHttp($this->user['uuid'], $item);
                $proxies[] = $httpConfig;
            }
        }
        foreach ($outbounds as &$outbound) {
            if (!in_array($outbound['type'], ['urltest', 'selector'])) {
                continue;
            }

            $include = $outbound['include'] ?? null;
            $exclude = $outbound['exclude'] ?? null;
            $fallback = $outbound['fallback'] ?? null;
            unset($outbound['include'], $outbound['exclude'], $outbound['fallback']);

            $allTags = array_column($proxies, 'tag');
            $tags = $allTags;

            if ($include !== null && $include !== '') {
                $tags = array_values(array_filter(
                    $tags,
                    fn($tag) => $this->matchesPattern($include, $tag)
                ));
            }

            if ($exclude !== null && $exclude !== '') {
                $tags = array_values(array_filter(
                    $tags,
                    fn($tag) => !$this->matchesPattern($exclude, $tag)
                ));
            }

            if (empty($tags) && $fallback !== null) {
                $tags = $this->resolveFallback($fallback, $allTags, $outbounds, $outbound['tag'] ?? '');
            }

            if (!empty($tags)) {
                array_push($outbound['outbounds'], ...$tags);
            }

            // sing-box rejects selector/urltest outbounds without any tags.
            // This can happen when every node is filtered out (or before the
            // first node has been provisioned), so keep the generated profile
            // importable with a direct fallback instead of emitting an
            // invalid configuration.
            $outbound['outbounds'] = array_values(array_unique(array_filter(
                $outbound['outbounds'] ?? [],
                fn ($tag) => is_string($tag) && $tag !== ''
            )));
            if (empty($outbound['outbounds'])) {
                $outbound['outbounds'] = ['direct'];
            }
            if ($outbound['type'] === 'selector') {
                $default = $outbound['default'] ?? null;
                if (!is_string($default) || !in_array($default, $outbound['outbounds'], true)) {
                    $outbound['default'] = $outbound['outbounds'][0];
                }
            }
        }
        unset($outbound);

        $outbounds = array_merge($outbounds, $proxies);
        $this->config['outbounds'] = $outbounds;
        return $outbounds;
    }

    /**
     * Safely match a user-supplied pattern against a node tag.
     *
     * Accepts either:
     *   - a bare pattern (e.g. "HK|香港") — wrapped with `~...~ui` delimiters
     *   - a fully-delimited pattern (e.g. "/foo/i", "#bar#u") — used as-is
     *
     * Uses `~` as the default delimiter (rare in node names) and escapes any
     * literal `~` in bare patterns. Invalid patterns never throw; they log a
     * warning and return false so the outbound simply stays empty rather than
     * breaking subscription generation.
     */
    protected function matchesPattern(string $pattern, string $subject): bool
    {
        static $cache = [];

        if (!isset($cache[$pattern])) {
            $trimmed = trim($pattern);
            $first = $trimmed !== '' ? $trimmed[0] : '';
            $looksDelimited = in_array($first, ['/', '#', '~', '@', '%'], true)
                && preg_match('/^(.)(.*)\1[a-zA-Z]*$/us', $trimmed) === 1;

            $cache[$pattern] = $looksDelimited
                ? $trimmed
                : '~' . str_replace('~', '\~', $pattern) . '~ui';
        }

        $compiled = $cache[$pattern];

        $result = @preg_match($compiled, $subject);

        if ($result === false) {
            $err = preg_last_error_msg();
            Log::warning("[SingBox] invalid outbound pattern {$pattern}: {$err}");
            $cache[$pattern] = '~(*FAIL)~';
            return false;
        }

        return $result === 1;
    }

    /**
     * Resolve a fallback value into a list of usable outbound tags.
     *
     * Accepted shapes (string or array, mixed freely):
     *   - "direct"                 → built-in outbound tag (direct/block/...)
     *   - "Singapore-03"           → exact node tag
     *   - "节点选择"                → another group's tag defined in template
     *   - "JP|日本"                → pattern matched against available node tags
     *   - ["HK-01", "JP-02"]       → list, each resolved in order, first hit wins
     *   - ["JP|日本", "direct"]    → pattern first, then hard fallback
     *
     * Returns the first non-empty resolution. Logs if nothing resolves.
     */
    protected function resolveFallback($fallback, array $allTags, array $outbounds, string $groupTag): array
    {
        $candidates = is_array($fallback) ? $fallback : [$fallback];
        $templateTags = array_column($outbounds, 'tag');

        foreach ($candidates as $candidate) {
            if (!is_string($candidate) || $candidate === '') {
                continue;
            }

            if (in_array($candidate, $allTags, true) || in_array($candidate, $templateTags, true)) {
                return [$candidate];
            }

            $matched = array_values(array_filter(
                $allTags,
                fn($tag) => $this->matchesPattern($candidate, $tag)
            ));

            if (!empty($matched)) {
                return $matched;
            }
        }

        Log::warning("[SingBox] outbound group '{$groupTag}' fallback unresolved; group left empty");
        return [];
    }

    /**
     * Build rule
     */
    protected function buildRule()
    {
        $rules = $this->config['route']['rules'];
        $this->config['route']['rules'] = $rules;
    }

    /**
     * 根据客户端版本自适应配置格式
     * 模板基准格式: 1.14.0+ (最新稳定版)
     */
    protected function adaptConfigForVersion(): void
    {
        // 没有版本信息时按当前稳定版处理，避免数据库中旧模板原样下发。
        $coreVersion = $this->getSingBoxCoreVersion() ?? '1.14.0';

        // Serve the bootstrap rule sets from the same panel host as the
        // subscription.  Clients that can fetch their subscription can then
        // start without first reaching GitHub or an already-running proxy.
        $this->usePanelHostedRuleSets();

        // >= 1.12.0 使用新的 DNS server 格式；1.14.0 已移除旧格式
        if (version_compare($coreVersion, '1.12.0', '>=')) {
            $this->upgradeDnsServersToCurrent();
            $this->upgradeDnsResolverRules();
            $this->removeEmptyDirectDnsDetours();
        }

        // >= 1.11.0: 将旧入站字段迁移为 route action
        if (version_compare($coreVersion, '1.11.0', '>=')) {
            $this->upgradeInboundFieldsToActions();
        }

        // >= 1.13.0: 移除已删除的 block/dns 出站
        if (version_compare($coreVersion, '1.13.0', '>=')) {
            $this->upgradeSpecialOutboundsToActions();
        }

        // >= 1.14.0: remote rule sets use the shared HTTP client.  The
        // dedicated client deliberately has no detour, so rule downloads do
        // not depend on a proxy outbound that has not started yet.
        if (version_compare($coreVersion, '1.14.0', '>=')) {
            $this->upgradeRuleSetHttpClient();
        }

        // < 1.14.0: shared HTTP clients are unavailable.  Keep remote rule
        // sets bootstrappable through the legacy direct download detour.
        if (version_compare($coreVersion, '1.14.0', '<')) {
            $this->downgradeRuleSetHttpClient();
        }

        // < 1.11.0: rule action 和入站 action 降级为旧格式
        if (version_compare($coreVersion, '1.11.0', '<')) {
            $this->downgradeInboundRuleActions();
            $this->downgradeActionsToSpecialOutbounds();
            $this->restoreDeprecatedInboundFields();
        }

        // < 1.12.0: 新 DNS server 和默认解析器降级为旧格式
        if (version_compare($coreVersion, '1.12.0', '<')) {
            $this->downgradeDnsRuleActions();
            $this->convertDnsServersToLegacy();
            $this->restoreLegacyDnsResolver();
        }

        // < 1.10.0: tun address 数组 → inet4_address/inet6_address
        if (version_compare($coreVersion, '1.10.0', '<')) {
            $this->convertTunAddressToLegacy();
        }
    }

    private function upgradeRuleSetHttpClient(): void
    {
        $ruleSets = $this->config['route']['rule_set'] ?? [];
        $usesDirectClient = false;

        foreach ($ruleSets as &$ruleSet) {
            if (($ruleSet['type'] ?? null) !== 'remote') {
                continue;
            }

            if (($ruleSet['download_detour'] ?? null) === '自动选择') {
                unset($ruleSet['download_detour']);
                $ruleSet['http_client'] = 'rule-set-direct';
            }

            if (($ruleSet['http_client'] ?? null) === 'rule-set-direct') {
                $usesDirectClient = true;
            }
        }
        unset($ruleSet);

        $this->config['route']['rule_set'] = $ruleSets;
        if (!$usesDirectClient) {
            return;
        }

        $clients = $this->config['http_clients'] ?? [];
        $hasDirectClient = false;
        foreach ($clients as $client) {
            if (($client['tag'] ?? null) === 'rule-set-direct') {
                $hasDirectClient = true;
                break;
            }
        }
        if (!$hasDirectClient) {
            $clients[] = [
                'tag' => 'rule-set-direct',
                'engine' => 'go',
                'connect_timeout' => '15s',
            ];
        }

        $this->config['http_clients'] = $clients;
        $this->config['route']['default_http_client'] = 'rule-set-direct';
    }

    private function usePanelHostedRuleSets(): void
    {
        if (!isset($this->config['route']['rule_set'])) {
            return;
        }

        $baseUrl = rtrim((string) (admin_setting('app_url') ?: request()->getSchemeAndHttpHost()), '/');
        $this->replaceOfficialRuleSetUrls($baseUrl);
    }

    private function replaceOfficialRuleSetUrls(string $baseUrl): void
    {
        $hostedRules = [
            'geosite-cn' => $baseUrl . '/rules/geosite-cn.srs',
            'geoip-cn' => $baseUrl . '/rules/geoip-cn.srs',
        ];

        foreach ($this->config['route']['rule_set'] as &$ruleSet) {
            $tag = $ruleSet['tag'] ?? null;
            $url = $ruleSet['url'] ?? null;
            if (!isset($hostedRules[$tag]) || !is_string($url)) {
                continue;
            }

            if (
                str_starts_with($url, 'https://raw.githubusercontent.com/SagerNet/')
                || str_starts_with($url, 'https://cdn.jsdelivr.net/gh/SagerNet/')
                || str_contains($url, '/rules/' . $tag . '.srs')
            ) {
                $ruleSet['url'] = $hostedRules[$tag];
            }
        }
        unset($ruleSet);
    }

    private function downgradeRuleSetHttpClient(): void
    {
        unset($this->config['http_clients'], $this->config['route']['default_http_client']);

        if (!isset($this->config['route']['rule_set'])) {
            return;
        }

        foreach ($this->config['route']['rule_set'] as &$ruleSet) {
            if (($ruleSet['http_client'] ?? null) !== 'rule-set-direct') {
                continue;
            }

            unset($ruleSet['http_client']);
            $ruleSet['download_detour'] = 'direct';
        }
        unset($ruleSet);
    }

    /**
     * 获取核心版本 (Hiddify/SFM 等映射到内核版本)
     */
    private function getSingBoxCoreVersion(): ?string
    {
        // 优先从 UA 提取核心版本
        if (!empty($this->userAgent)) {
            if (preg_match('/sing-box\s+v?(\d+(?:\.\d+){0,2})/i', $this->userAgent, $matches)) {
                return $matches[1];
            }
        }

        if (empty($this->clientVersion)) {
            return null;
        }

        if (in_array($this->clientName, ['sing-box', 'sfa', 'sfi', 'sfm'], true)) {
            return $this->clientVersion;
        }

        return '1.13.0';
    }

    /** sing-box >= 1.12.0: 旧 DNS server 转换为 type/server 格式。 */
    private function upgradeDnsServersToCurrent(): void
    {
        if (!isset($this->config['dns']['servers'])) {
            return;
        }

        $rcodeTags = [];
        foreach ($this->config['dns']['servers'] as &$server) {
            if (isset($server['type'])) {
                if ($server['type'] === 'rcode') {
                    $rcodeTags[$server['tag'] ?? ''] = strtoupper($server['rcode'] ?? 'success');
                    unset($server['type'], $server['rcode']);
                }
                continue;
            }

            $address = $server['address'] ?? null;
            if (!is_string($address) || $address === '') {
                continue;
            }

            if ($address === 'local') {
                $server['type'] = 'local';
                unset($server['address']);
                continue;
            }

            if (str_starts_with($address, 'rcode://')) {
                $rcodeTags[$server['tag'] ?? ''] = strtoupper(substr($address, 8) ?: 'success');
                unset($server['address']);
                continue;
            }

            if ($address === 'fakeip') {
                $server['type'] = 'fakeip';
                unset($server['address']);
                continue;
            }

            $parts = parse_url($address);
            $scheme = strtolower($parts['scheme'] ?? 'udp');
            $host = $parts['host'] ?? ($parts['path'] ?? $address);

            $server['type'] = match ($scheme) {
                'https' => 'https',
                'tls' => 'tls',
                'tcp' => 'tcp',
                'quic' => 'quic',
                'h3' => 'h3',
                'dhcp' => 'dhcp',
                'fakeip' => 'fakeip',
                default => 'udp',
            };
            if ($server['type'] !== 'dhcp') {
                $server['server'] = $host;
            } elseif ($host !== 'auto' && $host !== '') {
                $server['interface'] = $host;
            }
            if (isset($parts['port'])) {
                $server['server_port'] = (int) $parts['port'];
            }
            if ($server['type'] === 'https' || $server['type'] === 'h3') {
                $path = $parts['path'] ?? '';
                if ($path !== '' && $path !== '/dns-query') {
                    $server['path'] = $path;
                }
            }
            if (isset($server['address_resolver'])) {
                $server['domain_resolver'] = $server['address_resolver'];
                unset($server['address_resolver']);
            }
            if (isset($server['address_strategy'])) {
                $server['domain_strategy'] = $server['address_strategy'];
                unset($server['address_strategy']);
            }
            unset($server['address']);
        }
        unset($server);

        if (!empty($rcodeTags) && isset($this->config['dns']['rules'])) {
            foreach ($this->config['dns']['rules'] as &$rule) {
                $tag = $rule['server'] ?? '';
                if (!isset($rcodeTags[$tag])) {
                    continue;
                }
                unset($rule['server']);
                $rule['action'] = 'predefined';
                $rule['rcode'] = $rcodeTags[$tag];
            }
            unset($rule);
        }

        $this->config['dns']['servers'] = array_values(array_filter(
            $this->config['dns']['servers'],
            fn ($server) => isset($server['type'])
        ));
    }

    /** 将旧的 outbound DNS 规则迁移为全局默认解析器。 */
    private function upgradeDnsResolverRules(): void
    {
        $rules = $this->config['dns']['rules'] ?? [];
        $defaultResolver = null;
        $remaining = [];

        foreach ($rules as $rule) {
            $outbound = $rule['outbound'] ?? null;
            if ($outbound === ['any'] && isset($rule['server'])) {
                $defaultResolver ??= ['server' => $rule['server']];
                continue;
            }

            // `server` was implicit in older templates.  Since 1.11 it is a
            // DNS rule action field; make it explicit for current clients so
            // the profile remains valid after the 1.14 migration.
            if (isset($rule['server']) && !isset($rule['action'])) {
                $rule['action'] = 'route';
            }
            $remaining[] = $rule;
        }

        if ($defaultResolver !== null) {
            $this->config['route']['default_domain_resolver'] ??= $defaultResolver;
        }
        $this->config['dns']['rules'] = $remaining;
    }

    /**
     * Current sing-box releases reject DNS detours that point at an empty
     * direct outbound. Direct is already the default path in that case, so
     * removing the detour preserves the intended routing while allowing the
     * generated configuration to start. Keep detours to customized direct
     * outbounds because options such as bind_interface still have meaning.
     */
    private function removeEmptyDirectDnsDetours(): void
    {
        $emptyDirectTags = [];
        foreach ($this->config['outbounds'] ?? [] as $outbound) {
            if (($outbound['type'] ?? null) !== 'direct' || empty($outbound['tag'])) {
                continue;
            }

            $options = array_diff_key($outbound, array_flip(['type', 'tag']));
            if ($options === []) {
                $emptyDirectTags[$outbound['tag']] = true;
            }
        }

        if ($emptyDirectTags === [] || !isset($this->config['dns']['servers'])) {
            return;
        }

        foreach ($this->config['dns']['servers'] as &$server) {
            $detour = $server['detour'] ?? null;
            if (is_string($detour) && isset($emptyDirectTags[$detour])) {
                unset($server['detour']);
            }
        }
        unset($server);
    }

    /** 将 1.10 及更早的入站字段迁移为 1.11+ route action。 */
    private function upgradeInboundFieldsToActions(): void
    {
        if (!isset($this->config['inbounds'])) {
            return;
        }

        $actions = [];
        foreach ($this->config['inbounds'] as $index => &$inbound) {
            if (empty($inbound['tag'])) {
                $inbound['tag'] = 'in-' . $index;
            }
            $tag = $inbound['tag'];

            if (!empty($inbound['domain_strategy'])) {
                $actions[] = [
                    'inbound' => $tag,
                    'action' => 'resolve',
                    'strategy' => $inbound['domain_strategy'],
                ];
            }
            if (!empty($inbound['sniff'])) {
                $action = [
                    'inbound' => $tag,
                    'action' => 'sniff',
                ];
                if (!empty($inbound['sniff_timeout'])) {
                    $action['timeout'] = $inbound['sniff_timeout'];
                }
                $actions[] = $action;
            }

            unset(
                $inbound['domain_strategy'],
                $inbound['sniff'],
                $inbound['sniff_timeout'],
                $inbound['sniff_override_destination'],
                $inbound['endpoint_independent_nat']
            );
        }
        unset($inbound);

        if (!empty($actions)) {
            $this->config['route']['rules'] = array_merge(
                $actions,
                $this->config['route']['rules'] ?? []
            );
        }
    }

    /** sing-box >= 1.13.0: block/dns 出站升级为 action。 */
    private function upgradeSpecialOutboundsToActions(): void
    {
        $removedTags = [];
        $this->config['outbounds'] = array_values(array_filter(
            $this->config['outbounds'] ?? [],
            function ($outbound) use (&$removedTags) {
                if (in_array($outbound['type'] ?? '', ['block', 'dns'])) {
                    $removedTags[$outbound['tag']] = $outbound['type'];
                    return false;
                }
                return true;
            }
        ));

        if (empty($removedTags)) {
            return;
        }

        if (isset($this->config['route']['rules'])) {
            foreach ($this->config['route']['rules'] as &$rule) {
                if (!isset($rule['outbound']) || !isset($removedTags[$rule['outbound']])) {
                    continue;
                }
                $type = $removedTags[$rule['outbound']];
                unset($rule['outbound']);
                $rule['action'] = $type === 'dns' ? 'hijack-dns' : 'reject';
            }
            unset($rule);
        }
    }

    /** sing-box < 1.11.0: route action 降级为旧 outbound 字段。 */
    private function downgradeActionsToSpecialOutbounds(): void
    {
        $needsDnsOutbound = false;
        $needsBlockOutbound = false;

        if (isset($this->config['route']['rules'])) {
            foreach ($this->config['route']['rules'] as &$rule) {
                if (!isset($rule['action'])) {
                    continue;
                }
                switch ($rule['action']) {
                    case 'route':
                        unset($rule['action']);
                        break;
                    case 'hijack-dns':
                        unset($rule['action']);
                        $rule['outbound'] = 'dns-out';
                        $needsDnsOutbound = true;
                        break;
                    case 'reject':
                        unset($rule['action']);
                        $rule['outbound'] = 'block';
                        $needsBlockOutbound = true;
                        break;
                }
            }
            unset($rule);
        }

        if ($needsBlockOutbound) {
            $this->config['outbounds'][] = ['type' => 'block', 'tag' => 'block'];
        }
        if ($needsDnsOutbound) {
            $this->config['outbounds'][] = ['type' => 'dns', 'tag' => 'dns-out'];
        }
    }

    /** sing-box < 1.11.0: 将 sniff/resolve action 恢复为入站字段。 */
    private function downgradeInboundRuleActions(): void
    {
        if (!isset($this->config['inbounds'], $this->config['route']['rules'])) {
            return;
        }

        $inboundTags = array_values(array_filter(array_column($this->config['inbounds'], 'tag')));
        $sniffInbounds = [];
        $resolveStrategies = [];

        foreach ($this->config['route']['rules'] as $rule) {
            $action = $rule['action'] ?? null;
            if (!in_array($action, ['sniff', 'resolve'], true)) {
                continue;
            }

            $targets = $rule['inbound'] ?? $inboundTags;
            $targets = is_array($targets) ? $targets : [$targets];
            foreach ($targets as $tag) {
                if ($action === 'sniff') {
                    $sniffInbounds[$tag] = $rule['timeout'] ?? null;
                } else {
                    $resolveStrategies[$tag] = $rule['strategy'] ?? null;
                }
            }
        }

        foreach ($this->config['inbounds'] as &$inbound) {
            $tag = $inbound['tag'] ?? null;
            if ($tag !== null && array_key_exists($tag, $sniffInbounds)) {
                $inbound['sniff'] = true;
                if ($sniffInbounds[$tag] !== null) {
                    $inbound['sniff_timeout'] = $sniffInbounds[$tag];
                }
            }
            if ($tag !== null && array_key_exists($tag, $resolveStrategies)) {
                $inbound['domain_strategy'] = $resolveStrategies[$tag] ?? 'ipv4_only';
            }
        }
        unset($inbound);

        $this->config['route']['rules'] = array_values(array_filter(
            $this->config['route']['rules'],
            fn ($rule) => !in_array($rule['action'] ?? null, ['sniff', 'resolve'], true)
        ));
    }

    /** sing-box < 1.11.0: 恢复废弃的入站字段。 */
    private function restoreDeprecatedInboundFields(): void
    {
        if (!isset($this->config['inbounds'])) {
            return;
        }
        foreach ($this->config['inbounds'] as &$inbound) {
            if ($inbound['type'] === 'tun') {
                $inbound['endpoint_independent_nat'] = true;
            }
            if (!empty($inbound['sniff'])) {
                $inbound['sniff_override_destination'] = true;
            }
            if (!isset($inbound['domain_strategy'])) {
                $inbound['domain_strategy'] = 'ipv4_only';
            }
        }
        unset($inbound);
    }

    /** sing-box < 1.12.0: 将 predefined DNS action 降级为旧 DNS server。 */
    private function downgradeDnsRuleActions(): void
    {
        if (!isset($this->config['dns']['rules'])) {
            return;
        }

        $rcodeServers = [];
        foreach ($this->config['dns']['rules'] as &$rule) {
            if (($rule['action'] ?? null) !== 'predefined') {
                continue;
            }
            $rcode = strtolower($rule['rcode'] ?? 'success');
            $tag = 'dns-rcode-' . $rcode;
            $rcodeServers[$tag] = $rcode;
            unset($rule['action'], $rule['rcode']);
            $rule['server'] = $tag;
        }
        unset($rule);

        foreach ($rcodeServers as $tag => $rcode) {
            $this->config['dns']['servers'][] = [
                'address' => 'rcode://' . $rcode,
                'tag' => $tag,
            ];
        }
    }

    /** sing-box < 1.12.0: 恢复旧的 outbound DNS 解析规则。 */
    private function restoreLegacyDnsResolver(): void
    {
        unset($this->config['route']['default_domain_resolver']);
        $rules = $this->config['dns']['rules'] ?? [];
        foreach ($rules as $rule) {
            if (($rule['outbound'] ?? null) === ['any'] && ($rule['server'] ?? null) === 'local') {
                return;
            }
        }
        array_unshift($rules, [
            'outbound' => ['any'],
            'server' => 'local',
        ]);
        $this->config['dns']['rules'] = $rules;
    }

    /**
     * sing-box < 1.12.0: 将新 DNS server type+server 格式转换为旧 address 格式
     */
    private function convertDnsServersToLegacy(): void
    {
        if (!isset($this->config['dns']['servers'])) {
            return;
        }
        foreach ($this->config['dns']['servers'] as &$server) {
            if (!isset($server['type'])) {
                continue;
            }
            $type = $server['type'];
            $host = $server['server'] ?? null;
            switch ($type) {
                case 'local':
                    $server['address'] = 'local';
                    break;
                case 'https':
                    $server['address'] = "https://{$host}" . ($server['path'] ?? '/dns-query');
                    break;
                case 'tls':
                    $server['address'] = "tls://{$host}";
                    break;
                case 'tcp':
                    $server['address'] = "tcp://{$host}";
                    break;
                case 'quic':
                    $server['address'] = "quic://{$host}";
                    break;
                case 'h3':
                    $server['address'] = "h3://{$host}" . ($server['path'] ?? '/dns-query');
                    break;
                case 'udp':
                    $server['address'] = $host;
                    break;
                case 'dhcp':
                    $server['address'] = empty($server['interface'])
                        ? 'dhcp://auto'
                        : 'dhcp://' . $server['interface'];
                    break;
                case 'fakeip':
                    $server['address'] = 'fakeip';
                    break;
                case 'rcode':
                    $server['address'] = 'rcode://' . ($server['rcode'] ?? 'success');
                    unset($server['rcode']);
                    break;
                default:
                    $server['address'] = $host;
                    break;
            }
            unset(
                $server['type'],
                $server['server'],
                $server['server_port'],
                $server['path'],
                $server['interface'],
                $server['domain_resolver'],
                $server['domain_strategy']
            );
        }
        unset($server);
    }

    /**
     * sing-box < 1.10.0: 将 tun address 数组转换为 inet4_address/inet6_address
     */
    private function convertTunAddressToLegacy(): void
    {
        if (!isset($this->config['inbounds'])) {
            return;
        }
        foreach ($this->config['inbounds'] as &$inbound) {
            if ($inbound['type'] !== 'tun' || !isset($inbound['address'])) {
                continue;
            }
            foreach ($inbound['address'] as $addr) {
                if (str_contains($addr, ':')) {
                    $inbound['inet6_address'] = $addr;
                } else {
                    $inbound['inet4_address'] = $addr;
                }
            }
            unset($inbound['address']);
        }
    }

    protected function buildShadowsocks($password, $server)
    {
        $protocol_settings = data_get($server, 'protocol_settings');
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'shadowsocks';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['method'] = data_get($protocol_settings, 'cipher');
        $array['password'] = data_get($server, 'password', $password);
        if (data_get($protocol_settings, 'plugin') && data_get($protocol_settings, 'plugin_opts')) {
            $array['plugin'] = data_get($protocol_settings, 'plugin');
            $array['plugin_opts'] = data_get($protocol_settings, 'plugin_opts', '');
        }

        return $array;
    }


    protected function buildVmess($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $array = [
            'tag' => $server['name'],
            'type' => 'vmess',
            'server' => $server['host'],
            'server_port' => $server['port'],
            'uuid' => $uuid,
            'security' => 'auto',
            'alter_id' => 0,
        ];

        if ($protocol_settings['tls']) {
            $array['tls'] = [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls_settings.allow_insecure'),
            ];

            $this->appendUtls($array['tls'], $protocol_settings);
            $this->appendEch($array['tls'], data_get($protocol_settings, 'tls_settings.ech'));

            if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                $array['tls']['server_name'] = $serverName;
            }
        }

        $this->appendMultiplex($array, $protocol_settings);

        if ($transport = $this->buildTransport($protocol_settings, $server)) {
            $array['transport'] = $transport;
        }
        return $array;
    }

    protected function buildVless($password, $server)
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            "type" => "vless",
            "tag" => $server['name'],
            "server" => $server['host'],
            "server_port" => $server['port'],
            "uuid" => $password,
            "packet_encoding" => "xudp",
        ];
        if ($flow = data_get($protocol_settings, 'flow')) {
            $array['flow'] = $flow;
        }

        if (data_get($protocol_settings, 'tls')) {
            $tlsMode = (int) data_get($protocol_settings, 'tls', 0);
            $tlsConfig = [
                'enabled' => true,
                'insecure' => $tlsMode === 2
                    ? (bool) data_get($protocol_settings, 'reality_settings.allow_insecure', false)
                    : (bool) data_get($protocol_settings, 'tls_settings.allow_insecure', false),
            ];

            $this->appendUtls($tlsConfig, $protocol_settings);

            switch ($tlsMode) {
                case 1:
                    $this->appendEch($tlsConfig, data_get($protocol_settings, 'tls_settings.ech'));
                    if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                        $tlsConfig['server_name'] = $serverName;
                    }
                    break;
                case 2:
                    $tlsConfig['server_name'] = data_get($protocol_settings, 'reality_settings.server_name');
                    $tlsConfig['reality'] = [
                        'enabled' => true,
                        'public_key' => data_get($protocol_settings, 'reality_settings.public_key'),
                        'short_id' => data_get($protocol_settings, 'reality_settings.short_id')
                    ];
                    break;
            }

            $array['tls'] = $tlsConfig;
        }

        $this->appendMultiplex($array, $protocol_settings);

        if ($transport = $this->buildTransport($protocol_settings, $server)) {
            $array['transport'] = $transport;
        }

        return $array;
    }

    protected function buildTrojan($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $array = [
            'tag' => $server['name'],
            'type' => 'trojan',
            'server' => $server['host'],
            'server_port' => $server['port'],
            'password' => $password,
        ];

        $tlsMode = (int) data_get($protocol_settings, 'tls', 1);
        $tlsConfig = ['enabled' => true];

        switch ($tlsMode) {
            case 2: // Reality
                $tlsConfig['insecure'] = (bool) data_get($protocol_settings, 'reality_settings.allow_insecure', false);
                $tlsConfig['server_name'] = data_get($protocol_settings, 'reality_settings.server_name');
                $tlsConfig['reality'] = [
                    'enabled' => true,
                    'public_key' => data_get($protocol_settings, 'reality_settings.public_key'),
                    'short_id' => data_get($protocol_settings, 'reality_settings.short_id'),
                ];
                break;
            default: // Standard TLS
                $tlsConfig['insecure'] = (bool) data_get($protocol_settings, 'tls_settings.allow_insecure', false);
                $this->appendEch($tlsConfig, data_get($protocol_settings, 'tls_settings.ech'));
                if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                    $tlsConfig['server_name'] = $serverName;
                }
                break;
        }

        $this->appendUtls($tlsConfig, $protocol_settings);
        $array['tls'] = $tlsConfig;

        $this->appendMultiplex($array, $protocol_settings);

        if ($transport = $this->buildTransport($protocol_settings, $server)) {
            $array['transport'] = $transport;
        }
        return $array;
    }

    protected function buildHysteria($password, $server): array
    {
        $protocol_settings = $server['protocol_settings'];
        $baseConfig = [
            'server' => $server['host'],
            'server_port' => $server['port'],
            'tag' => $server['name'],
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls.allow_insecure', false),
            ]
        ];
        // 支持 1.11.0 版本及以上 `server_ports` 和 `hop_interval` 配置
        if ($this->supportsFeature('sing-box', '1.11.0')) {
            if (isset($server['ports'])) {
                $baseConfig['server_ports'] = [str_replace('-', ':', $server['ports'])];
            }
            if (isset($protocol_settings['hop_interval'])) {
                $baseConfig['hop_interval'] = "{$protocol_settings['hop_interval']}s";
            }
        }

        if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
            $baseConfig['tls']['server_name'] = $serverName;
        }
        $this->appendEch($baseConfig['tls'], data_get($protocol_settings, 'tls.ech'));
        $speedConfig = [
            'up_mbps' => data_get($protocol_settings, 'bandwidth.up'),
            'down_mbps' => data_get($protocol_settings, 'bandwidth.down'),
        ];
        $versionConfig = match (data_get($protocol_settings, 'version', 1)) {
            2 => [
                'type' => 'hysteria2',
                'password' => $password,
                'obfs' => data_get($protocol_settings, 'obfs.open') ? [
                    'type' => data_get($protocol_settings, 'obfs.type'),
                    'password' => data_get($protocol_settings, 'obfs.password')
                ] : null,
            ],
            default => [
                'type' => 'hysteria',
                'auth_str' => $password,
                'obfs' => data_get($protocol_settings, 'obfs.password'),
                'disable_mtu_discovery' => true,
            ]
        };

        return array_filter(
            array_merge($baseConfig, $speedConfig, $versionConfig),
            fn($v) => !is_null($v)
        );
    }

    protected function buildTuic($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'tuic',
            'tag' => $server['name'],
            'server' => $server['host'],
            'server_port' => $server['port'],
            'congestion_control' => data_get($protocol_settings, 'congestion_control', 'cubic'),
            'udp_relay_mode' => data_get($protocol_settings, 'udp_relay_mode', 'native'),
            'zero_rtt_handshake' => true,
            'heartbeat' => '10s',
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls.allow_insecure', false),
                'alpn' => data_get($protocol_settings, 'alpn', ['h3']),
            ]
        ];

        if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
            $array['tls']['server_name'] = $serverName;
        }
        $this->appendEch($array['tls'], data_get($protocol_settings, 'tls.ech'));

        if (data_get($protocol_settings, 'version') === 4) {
            $array['token'] = $password;
        } else {
            $array['uuid'] = $password;
            $array['password'] = $password;
        }

        return $array;
    }

    protected function buildAnyTLS($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'anytls',
            'tag' => $server['name'],
            'server' => $server['host'],
            'password' => $password,
            'server_port' => $server['port'],
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls.allow_insecure', false),
                'alpn' => data_get($protocol_settings, 'alpn', ['h3']),
            ]
        ];

        if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
            $array['tls']['server_name'] = $serverName;
        }
        $this->appendEch($array['tls'], data_get($protocol_settings, 'tls.ech'));

        return $array;
    }

    protected function buildSocks($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'socks',
            'tag' => $server['name'],
            'server' => $server['host'],
            'server_port' => $server['port'],
            'version' => '5', // 默认使用 socks5
            'username' => $password,
            'password' => $password,
        ];

        if (data_get($protocol_settings, 'udp_over_tcp')) {
            $array['udp_over_tcp'] = true;
        }

        return $array;
    }

    protected function buildHttp($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'http',
            'tag' => $server['name'],
            'server' => $server['host'],
            'server_port' => $server['port'],
            'username' => $password,
            'password' => $password,
        ];

        if ($path = data_get($protocol_settings, 'path')) {
            $array['path'] = $path;
        }

        if ($headers = data_get($protocol_settings, 'headers')) {
            $array['headers'] = $headers;
        }

        if (data_get($protocol_settings, 'tls')) {
            $array['tls'] = [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls_settings.allow_insecure', false),
            ];

            if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                $array['tls']['server_name'] = $serverName;
            }
            $this->appendEch($array['tls'], data_get($protocol_settings, 'tls_settings.ech'));
        }

        return $array;
    }

    protected function buildTransport(array $protocol_settings, array $server): ?array
    {
        $transport = match (data_get($protocol_settings, 'network')) {
            'tcp' => data_get($protocol_settings, 'network_settings.header.type') === 'http' ? [
                'type' => 'http',
                'path' => Arr::random(data_get($protocol_settings, 'network_settings.header.request.path', ['/'])),
                'host' => data_get($protocol_settings, 'network_settings.header.request.headers.Host', [])
            ] : null,
            'ws' => [
                'type' => 'ws',
                'path' => data_get($protocol_settings, 'network_settings.path'),
                'headers' => ($host = data_get($protocol_settings, 'network_settings.headers.Host')) ? ['Host' => $host] : null,
                'max_early_data' => 0,
                // 'early_data_header_name' => 'Sec-WebSocket-Protocol'
            ],
            'grpc' => [
                'type' => 'grpc',
                'service_name' => data_get($protocol_settings, 'network_settings.serviceName')
            ],
            'h2' => [
                'type' => 'http',
                'host' => data_get($protocol_settings, 'network_settings.host'),
                'path' => data_get($protocol_settings, 'network_settings.path')
            ],
            'httpupgrade' => [
                'type' => 'httpupgrade',
                'path' => data_get($protocol_settings, 'network_settings.path'),
                'host' => data_get($protocol_settings, 'network_settings.host', $server['host']),
                'headers' => data_get($protocol_settings, 'network_settings.headers')
            ],
            'quic' => ['type' => 'quic'],
            default => null
        };

        if (!$transport) {
            return null;
        }

        return array_filter($transport, fn($v) => !is_null($v));
    }

    protected function appendMultiplex(&$array, $protocol_settings)
    {
        if ($multiplex = data_get($protocol_settings, 'multiplex')) {
            if (data_get($multiplex, 'enabled')) {
                $array['multiplex'] = [
                    'enabled' => true,
                    'protocol' => data_get($multiplex, 'protocol', 'yamux'),
                    'max_connections' => data_get($multiplex, 'max_connections'),
                    'min_streams' => data_get($multiplex, 'min_streams'),
                    'max_streams' => data_get($multiplex, 'max_streams'),
                    'padding' => (bool) data_get($multiplex, 'padding', false),
                ];
                if (data_get($multiplex, 'brutal.enabled')) {
                    $array['multiplex']['brutal'] = [
                        'enabled' => true,
                        'up_mbps' => data_get($multiplex, 'brutal.up_mbps'),
                        'down_mbps' => data_get($multiplex, 'brutal.down_mbps'),
                    ];
                }
                $array['multiplex'] = array_filter($array['multiplex'], fn($v) => !is_null($v));
            }
        }
    }

    protected function appendUtls(&$tlsConfig, $protocol_settings)
    {
        if ($utls = data_get($protocol_settings, 'utls')) {
            if (data_get($utls, 'enabled')) {
                $tlsConfig['utls'] = [
                    'enabled' => true,
                    'fingerprint' => Helper::getTlsFingerprint($utls)
                ];
            }
        }
    }

    protected function appendEch(&$tlsConfig, $ech): void
    {
        if ($normalized = Helper::normalizeEchSettings($ech)) {
            // Client outbound only needs the public ECH config, not the server's private key
            $tlsConfig['ech'] = array_filter([
                'enabled' => true,
                'config' => data_get($normalized, 'config') ? [data_get($normalized, 'config')] : null,
                'query_server_name' => data_get($normalized, 'query_server_name'),
            ], fn($value) => $value !== null);
        }
    }
}
