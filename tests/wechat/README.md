# 微信与会员能力回归

这些测试启动真实 Casdoor HTTP/HTTPS 进程并读写独立 MySQL；微信 HTTP 响应由测试 transport 模拟。它们证明实现、持久化和令牌契约，不能代替真人微信、真实手机号授权或共享实例验收。

## 隔离资源

使用独立 MySQL 8.0 容器，端口仅绑定本机回环；不要使用共享数据库或对共享账号表执行清理。通过受保护进程环境注入 `CASDOOR_WECHAT_TEST_DSN`，格式为 `用户:密码@tcp(127.0.0.1:隔离端口)/`。入口拒绝非回环 TCP 和指定数据库名，固定建库 `casdoor_probe`。同一实例内的应用和组织使用每轮唯一测试名称。

```sh
go test ./tests/wechat -run TestProbeDSNIsolation -count=1
go test ./tests/wechat -run '^TestWechat' -count=1 -v
go vet ./tests/wechat ./controllers ./object ./idp
go build .
```

未注入 DSN 时依赖数据库的测试会 Skip；必须检查实际通过数和 Skip，不能将退出码为零当作集成验收。`TestWechatProcessHelper` 只在父测试启动的子进程中执行，常规全套调用会单独 Skip 此入口。`TestWechatIndependentProcesses` 启动两个独立进程共享该数据库，验证首次建号锁、最终账号和关联记录；其他回归覆盖注册顺序、UnionID 补齐与冲突、逐 AppID 查询、JWT-Custom、手机号、资料、人脸版本、封禁、刷新和应用级撤销。

## 跨服务互操作

`TestXuedaMemberHTTPInterop` 还需要 `XUEDA_MEMBER_INTEROP_REPO` 指向对应 Xueda 工作区，测试由真实签发令牌进入正式 HTTP 路由。`TestAirshipMemberFaceHTTPInterop` 需要 `AIRSHIP_MEMBER_INTEROP_REPO` 指向对应 Airship 工作区，并通过该仓库 integration 测试要求的独立 MySQL、MQTT 和 AMQPS 环境配置。先阅读两个互操作测试中的环境变量要求。

```sh
go test ./tests/wechat -run '^TestXuedaMemberHTTPInterop$' -count=1 -v
go test ./tests/wechat -run '^TestAirshipMemberFaceHTTPInterop$' -count=1 -v
```

Device 回归检查受限原图查询、TLS、服务凭据、当前版本摘要、过期引用、替换和删除；接口受理不代表实际设备 ACK 或现场通行。

测试结束后停止本轮子进程和隔离容器，移除其独立卷及受保护的临时凭据。只保留脱敏结论、测试方法和代码提交，不提交完整 JWT、Provider Secret、二维码票据、手机号、人脸图片或原始日志。
