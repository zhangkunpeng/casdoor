# 微信与会员能力回归

这些测试启动真实 Casdoor HTTP 入口并读写独立 MySQL；微信 HTTP 响应由测试 transport 模拟。它们证明实现、持久化和令牌契约，不能代替真人微信、真实手机号授权或共享实例验收。

## 隔离资源

使用独立 MySQL 8.0/8.4 实例，端口仅绑定本机回环；不要使用共享数据库或对共享账号表执行清理。通过受保护进程环境注入 `CASDOOR_WECHAT_TEST_DSN`，格式为 `用户:密码@tcp(127.0.0.1:隔离端口)/`。入口拒绝非回环 TCP 和指定数据库名，固定建库 `casdoor_probe`。同一实例内的应用和组织使用每轮唯一测试名称。

```sh
go test ./tests/wechat -run TestProbeDSNIsolation -count=1
go test ./tests/wechat -run '^TestWechat' -count=1 -v
go vet ./tests/wechat ./controllers ./object ./idp
go build .
```

未注入 DSN 时依赖数据库的测试会 Skip；必须检查实际通过数和 Skip，不能将退出码为零当作集成验收。`TestWechatProcessHelper` 只在父测试启动的子进程中执行，常规全套调用会单独 Skip 此入口。`TestWechatIndependentProcesses` 启动两个独立进程共享该数据库，验证首次建号锁、最终账号和原生属性；其他回归覆盖注册顺序、UnionID 补齐与冲突、逐 AppID 查询、JWT-Custom、手机号、资料、人脸版本、封禁及原生刷新与撤销。

刷新与撤销生产实现与官方 v4.26.0 一致。开启轮换时删除父令牌；用已删除父令牌撤销不会影响后继，须提交当前令牌。禁用轮换时保留并复用同一刷新令牌，原生撤销会使共享该刷新令牌摘要的 Token 一起失效。回归仅验证这些原生边界，不要求服务端原子轮换、并发单次消费或会话家族撤销。原生撤销数据库错误返回 HTTP 200 的 `status:error`，消费方需识别响应体中的失败。

## 跨服务互操作

`TestXuedaMemberHTTPInterop` 需要 `XUEDA_MEMBER_INTEROP_REPO` 指向对应 Xueda 工作区，测试由真实签发令牌进入正式 HTTP 路由。账号、当前角色/权限和目录使用原生 `get-user/get-users`；本人资料和人脸使用原生 `update-user`，经正式认证与授权过滤器执行。原图使用临时目录中的原生 Local File System Provider，通过 `upload-resource` 上传并经 HTTP 回读，测试结束后清理临时资源。

```sh
go test ./tests/wechat -run '^TestXuedaMemberHTTPInterop$' -count=1 -v
```

Device 只消费 Xueda 提供的通用取图 URL，不持有 Casdoor 凭据，本仓库不提供 Device 专用接口。

## 扩展边界

基线为官方 `v4.26.0`，不新增数据库表。现存主体通过原生用户表的二进制 `Id` 与组织内唯一索引保护，硬删除后不保留历史 ID。仅新增 `member-phone`，复用原生小程序 `GetPhoneNumber` 验证并更新当前账号；失败后须重新授权新 code，不保存操作账本或可信证明，原生解析保存 ISO 地区码。微信上游凭据只在进程内使用，不对外提供、不持久化。权限复用原生 `Application.Scopes`，名称为 `phone:write`；扩展入口只接受明确配置的精确名称，空列表与通配符不授权。

OpenID 使用原生 `get-user?owner=<组织>&userId=<主体>` 返回的 `properties.oauth_WeChat_extra` JSON 字符串，按固定 AppID 解析 `wechat_openid_<AppID>`；不使用通用微信 ID 或其他应用的值。微信登录直接查找原生属性，首次用户插入同时保存别名，后续沿用原生属性合并；缺失 UnionID 不覆盖已验证值。回归验证多 AppID 保留、本人修改拒绝与字段过滤。组织的 Properties 必须只允许管理员修改，且服务端查询身份有权查看；属性被过滤时不得回退其他来源。

注册锁使用由数据库 Adapter 持有和关闭的独立 MySQL 连接池，每进程最多两条连接；持锁者和等待者不占用业务池。身份关联保存后释放锁，角色加载、MFA 和令牌签发继续沿用原生流程。回归在业务池上限为 1、2 时验证查询可继续执行，并验证同组织等待和跨进程首次注册。

手机号与原生用户更新共用接受当前 session 的持久化入口；Hash 所需的 Syncer 查询也使用同一事务连接。回归启用 Phone/CountryCode 哈希映射，在单连接业务池下验证 Hash、UpdatedTime、失败回滚和新授权恢复。按手机号关联已有账号时，规范化微信身份与逐 AppID 别名一次保存；有、无 UnionID 的故障注入均验证失败后账号保持未绑定，新授权可关联原主体。

扩展入口的 scope 检查只约束 `member-phone`。原生 OAuth 沿用自己的 scope 校验；普通 Application 的 Basic 凭据在原生 API 上仍具有本组织管理权限，不能将其宣称为只读或全局最小授权。生产凭据必须只保存在服务端。

测试结束后停止本轮子进程和隔离容器，移除其独立卷及受保护的临时凭据。只保留脱敏结论、测试方法和代码提交，不提交完整 JWT、Provider Secret、二维码票据、手机号、人脸图片或原始日志。
