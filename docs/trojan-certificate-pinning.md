# Trojan 内容推送证书指纹

Trojan 标准 TLS 节点在管理页面保存内容推送证书后，通用订阅会自动输出
`pcs`（Xray 的 `pinnedPeerCertSha256`），供支持该参数的客户端固定信任节点证书。
3x-ui 已支持把 `pcs` 导入对应的 Xray 出站字段。

## 管理页面配置

1. 编辑 Trojan 节点，使用标准 TLS，而非 Reality。
2. 打开「高级协议配置 → TLS」，证书模式选择 `content (Cert Push)`。
3. 填入证书及匹配私钥。新节点也可填写证书域名并点击「自动生成」。
4. 点击高级设置的 Save，再提交节点配置。生成按钮只填表，不会直接保存或下发。
5. 等节点应用证书后，在 3x-ui 刷新该订阅。

现有有效内容证书可以直接使用，无须重新生成。前端无需另填 `pcs`；后端每次生成订阅时
根据已保存的公开叶子证书计算指纹。证书轮换后应待服务端应用新证书，再刷新客户端订阅。

例如，通用链接包含：

```text
trojan://PASSWORD@192.0.2.10:37165?pcs=<证书SHA256>&allowInsecure=1&peer=node.example.com&sni=node.example.com&fp=chrome#trojan-content
```

`pcs` 是证书链第一张证书 DER 内容的 SHA-256，格式为 64 位小写十六进制。
它不是 `fp=chrome` 这样的 TLS 客户端指纹，也不是私钥、公钥或 PEM 文本的哈希。
证书 PEM 和私钥均不会写入订阅链接。

## 范围和兼容性

- 支持 `flag=general` 及同一生成器的别名；原有 SNI、传输参数、uTLS 和
  `allowInsecure` 设置继续保留。当前 Xray 使用证书固定配置，不能只依赖 `allowInsecure`。
- `cert_config.cert_mode` 和旧的 `cert_config.mode` 均支持。
- 保存标准 TLS Trojan 的内容证书时，校验证书和匹配私钥，并保留完整的 `cert_config`。
  历史无效内容证书会使订阅生成报错，需先修复证书，避免静默输出没有指纹的链接。
- `self`、`http`、`dns`、`file`、`none` 等模式不根据遗留内容生成指纹；这些模式下
  面板不一定持有服务端当前实际使用的证书。Reality 不使用本功能。
- 本次不扩展 Shadowrocket、Clash、sing-box 等其他格式的证书导出行为。
- 这修复 Trojan 的证书信任配置，不会改变 Hysteria2 的底层 UDP 路径。

## 验证

```bash
php vendor/bin/phpunit --bootstrap vendor/autoload.php --no-configuration \
  --do-not-cache-result tests/Unit/Protocols
```

回归覆盖管理表单保存、完整 base64 订阅、字段保留、证书链及轮换、无效证书和不匹配私钥、
非内容模式与 Reality，以及旧版未显式填写 TLS 模式的 Trojan 配置。

代码在 `Xboard` 子模块中。发布需要更新该子模块版本、构建并发布应用镜像；
部署新版本后，已有有效内容证书节点无需重新保存，下一次订阅刷新即可取得 `pcs`。
