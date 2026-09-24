# 节点 HTTP 真实测试

节点管理每行的「操作 → HTTP 真实测试」会启动一次手动测试。状态圆点的浮层
展示最近结果、HTTP 状态码、耗时、完成时间、固定目标地址及测试来源。
原有上报在线状态、CPU/内存、WS/内核状态仍独立显示，不能等同于代理可用性。

## 测试路径与结果

面板服务器启动隔离的 sing-box **1.14.0**，通过该节点的实际订阅连接地址、
端口、协议、TLS/ECH、混淆及认证参数请求
`https://www.gstatic.com/generate_204`。仅 HTTPS 验证通过且返回 **204** 时成功。
HTTP 503 等非预期响应保留真实状态码；无 HTTP 响应时区分超时、证书、认证、
拒绝连接、解析等错误（部分握手错误只能归类为代理连接失败）。

- 使用现有 SingBox 协议生成器，但不加载订阅路由模板、分流、自动选择、TUN
  或直连回退；测试失败不能自动切换到其他节点。
- 优先使用属于该节点有效用户列表的当前管理员；否则使用列表中的首个有效用户。
  不创建账号、不修改权限组、不启用停用节点。产生少量连接/流量，计入被选用户；
  管理员 API 结果含 `test_user_id`，不含 UUID 或密码。
- 无有效用户、停用、配额耗尽、不支持的协议或测试运行环境缺失返回“无法测试”，
  不据此判定网络不通。sing-box 不支持的 xHTTP、Naive/Mieru 等不能测试。
- Hysteria2 使用真实 QUIC/UDP 代理传输；Trojan 使用其配置对应的 TCP/TLS 传输。
  测试目标是 HTTPS，不是独立的 UDP echo/ping。
- 结果是**面板服务器所在网络**的可达性，不代表 Android 或其他客户端网络。
  包含握手、目标连接及 HTTPS 请求的耗时，不是纯 TCP RTT 或吞吐测速。
- 缓存保留 24 小时；超过 5 分钟或节点配置变化标为“历史结果”。手动点击才测试，
  查询列表/悬浮不会自动访问节点。

## 接口与资源限制

管理员鉴权组内新增 `POST /api/v2/{secure_path}/server/manage/testHttp`，请求仅含
`{"id":17}`。目标地址不接受浏览器输入，不跟随 HTTP 重定向。`getNodes` 给每个
节点追加 `http_test`（未测试时为 null）。无需数据库迁移或 Xboard-Node 更新。

一次请求最多等待 3 秒启动及 12 秒 HTTP；跨 worker 使用缓存锁限制一个并发测试，
同节点 15 秒内限一次。忙碌/频繁请求返回 429。临时目录 0700、配置 0600，
短暂 SOCKS 端口仅监听 127.0.0.1 并使用随机认证，退出后关闭进程并删除配置。
原始内核日志/命令行不传给前端，避免凭据泄漏。

## 构建与配置

主仓库 Dockerfile 从官方固定版本及 digest 镜像复制 sing-box 并检查版本；
确保 PHP cURL 与系统 CA 已安装。非 Docker 环境可通过 `NODE_PROBE_SING_BOX`
指定 1.14.0 可执行文件；私有 CA 环境可设置 `NODE_PROBE_CA_BUNDLE`。
生产不能关闭测试目标的 TLS 证书验证。

前端改动位于独立 `public/assets/admin` 子仓：`node-http-probe.mjs` 是可维护源码，
生成的 `assets/index-http-probe-*.js` 是实际加载的完整包。Xboard 仓库中的
`node scripts/patch-admin-http-probe.mjs` 将源码嵌入分发包并更新 manifest/index.html，
保留现有证书生成按钮和旧版资产。Docker 构建不再执行此补丁。
发布需先提交管理端子仓，再提交 Xboard 子模块指针，最后提交主仓库指针和 Dockerfile。

## 验证

```sh
vendor/bin/phpunit --bootstrap vendor/autoload.php tests/Unit/Services/NodeHttpProbeTest.php
node --test tests/theme/node-http-probe.test.mjs
NODE_PROBE_SING_BOX=/path/to/sing-box-1.14.0 php tests/smoke/node-http-probe.php
PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs node tests/theme/node-http-probe.browser.mjs
```

端到端测试使用本地 HTTPS 服务器、Trojan 和带 Salamander 混淆的 Hysteria2
服务端，验证 204、503、目标 TLS 验证、错误认证无直连回退、临时文件清理。
浏览器测试使用真实管理端包和模拟 API，不访问生产账号；覆盖菜单、加载状态、
成功/失败浮层、刷新保留和历史结果。截图位于 `/tmp/xboard-node-http-*.png`。
