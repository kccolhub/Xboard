# Hysteria 2 内容推送证书指纹

Hysteria 2 节点在「高级设置 → TLS」选择 `content (Cert Push)` 并填写有效的
PEM 证书及匹配私钥后，通用订阅（`flag=general` 及其别名）和小火箭订阅
（`flag=shadowrocket`）会自动在分享链接中加入 `pinSHA256`。

指纹是证书链中第一张（节点叶证书）DER 数据的 SHA-256，输出为 64 位小写十六进制。
不对 PEM 文本、私钥或公钥单独求哈希，也不向订阅暴露证书内容或私钥。
`cert_config.mode` 和 `cert_config.cert_mode` 两种字段名均受支持。
证书内容变更后，下次订阅请求会重新计算指纹；客户端需刷新订阅。

## 管理界面自动生成

在「高级协议配置 → TLS」选择 `content (Cert Push)`，输入证书域名，点击输入框右侧的
「自动生成」。后台生成该域名的自签名证书及匹配私钥，自动填入下方两个文本框。
域名为空时按钮禁用；生成过程中若修改域名、模式或证书内容，返回结果不会覆盖修改。

生成操作只填表，不保存节点或立即下发。确认内容后点击 Save、提交节点配置，待节点应用证书后
刷新客户端订阅。再次生成并保存会更换证书与指纹，已有客户端也需要刷新订阅。

证书使用 EC P-256 密钥，有效期 3650 天，包含输入域名或 IP 的 SAN。它是自签名证书，
不是公共 CA 签发的证书，不需要 DNS 验证。客户端通过订阅中的证书指纹固定信任。

生成接口为管理员鉴权保护的 `POST /api/v2/<管理路径>/server/manage/generateCertificate`，
请求体为 `{"domain":"node.example.com"}`。响应禁止缓存；私钥仅返回管理员表单，不进入订阅。

## 管理界面版本管理

管理界面子模块 `public/assets/admin` 使用组织 fork：
`https://github.com/kccolhub/xboard-admin-dist` 的 `kccolhub/main` 分支。
按钮可读源码 `certificate-generator.mjs` 和包含该按钮的编译产物均直接提交在此仓库中。
入口使用新的内容哈希文件名，并同步更新 manifest 和 HTML，以避免旧资源缓存。

发布时先提交管理前端，再更新 Xboard 的子模块引用，最后更新外层
`micro-service-xboard` 的 Xboard 引用。正常递归检出即可获得前端改动，
不需要构建时打补丁，也不修改原有 Docker 构建流程。

## 订阅参数

例如，配置上行 100 Mbps、允许不安全、Salamander 混淆、SNI 留空后，链接形如：

```text
hysteria2://PASSWORD@192.0.2.10:57683?insecure=1&upmbps=100&security=tls&pinSHA256=<实际证书的64位SHA256>&disable_sni=1&fastopen=0&obfs=salamander&obfs-password=OBFS_PASSWORD#hysteria2-internal-3
```

- 已配置的正数上/下行带宽分别输出为 `upmbps` / `downmbps`。
- 内容推送指纹链接附带 `security=tls`、`fastopen=0`。
- SNI 留空时输出 `disable_sni=1`；有 SNI 时保留原名称并输出 `disable_sni=0`。
  通用格式用 `sni`，小火箭格式沿用 `peer`。
- `insecure` 保留面板中「允许不安全」设置，不强制修改。
- 混淆、端口跳跃等原有参数继续保留。参数顺序不影响含义。
- 客户端须支持证书固定及相应链接参数。当前 3x-ui 可导入 `pinSHA256`，但不解析
  `disable_sni`、`fastopen` 等所有客户端扩展参数；这些参数不代表该客户端必然启用对应行为。
- 保存 Hysteria 2 内容推送节点时会校验 PEM 证书。历史数据若存在缺失或无效的内容证书，
  会使该订阅生成失败，避免静默下发缺少指纹的不安全链接；请修正节点证书后重试。
- `self`、`http`、`dns`、`file` 等模式不自动生成指纹；Xboard 没有节点实际证书。
  Hysteria 1、其他协议以及 YAML/JSON 订阅不在此次改动范围内。

验证：

```bash
php vendor/bin/phpunit --bootstrap vendor/autoload.php --no-configuration \
  --do-not-cache-result tests/Unit/Protocols
node --test tests/theme/certificate-generator.test.mjs
```

本地预览使用实际分发包提取的证书面板组件及实际生成函数，验证按钮位置、生成后填表及切换模式隐藏按钮；
预览中的基础 UI 组件为替代实现，尚未在已部署的完整管理界面进行验证。
