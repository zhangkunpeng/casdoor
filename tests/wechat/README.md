# 微信登录与手机号绑定

扩展基于官方 Casdoor v4.26.0，仅支持同一组织内的小程序、公众号按可信 UnionID 登录同一账号，以及小程序授权手机号绑定。用户表沿用原版，通用用户 API 保持原生语义，无 UnionID 的 OpenID 查找和持久化沿用原版。UnionID 仅查询原生微信字段及已有 `properties.wechatUnionId`；小程序保留原生 OpenID 存储。无 UnionID 时不增加 AppID 前缀或别名规则。原生 `WeChat` 字段只保存一个 OpenID：小程序补齐 UnionID 后继续保存小程序 OpenID；后续公众号若缺失 UnionID，仍只按该原生字段查找，不承诺跨渠道缺失 UnionID 时的同人识别。

公众号扫码回调通过该公众号凭据查询微信用户信息；需有 `cgi-bin/user/info` 权限并与小程序绑定同一微信开放平台。回调保留可信 OpenID；微信返回 UnionID 时优先按 UnionID 查找，未匹配时沿用原生 OpenID 查找并补齐 UnionID。查询失败或返回不匹配的 OpenID 时拒绝本次回调。token 与用户信息查询均使用 10 秒超时。

有 UnionID 的首次登录通过 MySQL advisory lock 防止跨进程重复建号；锁仅覆盖同一数据库、组织、UnionID，使用临时独立连接，退出登录流程时关闭连接释放。无 UnionID 不加锁。本扩展的 UnionID 登录要求 MySQL；不自动合并已存在的重复账号。

`Properties` 须保留原生仅管理员修改的配置。局部用户更新复制 Properties map，确保原生权限检查比较的是更新前后的两个值，防止本人伪造用于登录匹配的 UnionID；不新增权限框架。

`POST /api/login/oauth/member-phone` 由服务端调用，使用应用 Basic 凭据，并提交 `token`、该应用配置的小程序 `app_id` 和微信 `getPhoneNumber` 授权 `code`。`token` 是操作对象的用户访问令牌；不发送旧 `access_token`/`accessToken` 参数或 Cookie。仅更新有效用户访问令牌所属账号，应用令牌和 ID-JAG 不能授权绑定。DPoP 令牌须携带与请求 method、URI、访问令牌及绑定密钥匹配的原生证明。Basic 凭据必须保存在服务端，不新增 `phone:write` scope。

微信换号完成后，在同一事务内复核原账号主体、令牌有效期与撤销状态、账号禁用与删除状态，再复用原生手机号规范化与唯一性规则写入；同一组织的绑定通过组织行锁串行提交。OAuth 资料同步、小程序补齐和后续 Provider 绑定均锁定当前账号，按实际变更的字段保存，并用同一 Session 生成原生 Hash 和更新时间。无 UnionID 的旧请求保留已补齐的 UnionID。永久头像仍沿用原生共享路径及上传规则，上传在用户事务外执行；数据库回滚不撤回头像文件覆盖。本轮不改变通用用户 API 或管理员写入的并发语义。

成功返回 `{"phoneBound":true}`；输入无效或手机号已被本组织其他账号使用、用户令牌无效、未配置的小程序分别返回 400、401、403；微信或数据库失败返回 503。错误应用凭据保留原生 `invalid_client` 认证错误，不归类为用户会话失效。微信 code 是一次性的，换号后校验或数据库写入失败须重新授权新 code。新 code 验证出已经绑定的手机号时正常返回成功，消费过的 code 仍由微信拒绝。Hash 配置读取和写入共用绑定事务的连接，配置读取完成后再复核令牌有效期。

## 回归验证

测试使用真实 Casdoor HTTP、真实独立 MySQL，以及模拟微信响应，不代替真人微信授权验收。`CASDOOR_WECHAT_TEST_DSN` 必须指向回环 IP 的独立 MySQL 实例且不包含库名；测试创建 `casdoor_probe`。

```sh
go test ./tests/wechat ./idp -run 'TestWechat|TestOfficialAccount|TestResolveWechatOfficialAccountIdentity' -count=1 -v
go test -race ./tests/wechat ./idp -run 'TestWechat|TestOfficialAccount|TestResolveWechatOfficialAccountIdentity' -count=1
go vet ./tests/wechat ./controllers ./object ./idp
go test ./object -run '^TestUserMutationSQLiteLocksBeforeReading$' -count=1
go build -o /tmp/casdoor-server .
```

未提供 DSN 时 MySQL 测试跳过；SQLite 锁测试使用独立临时文件。`TestWechatProcessHelper` 由 `TestWechatUnionIDAcrossProcesses` 实际启动两次，`TestWechatMemberPhoneSingleConnectionHelper` 由单连接绑定测试启动，单独调用时跳过。测试覆盖用户表原生结构、两种注册顺序、并发注册、UnionID 补齐和旧快照交错、无 UnionID 原生行为、原生用户与应用铸造来源和四种 TokenFormat、刷新、DPoP、正式认证过滤器、OAuth mapping/Provider 绑定、手机号选中账号后的变更拒绝、手机号持久化与 Hash/更新时间、原生规范化与唯一性一致性、并发争用手机号、换号期间用户名复用/封禁/删除/撤销/过期、元数据读取期间过期、单连接池、新 code 绑定相同手机号、错误令牌、错误应用、消费 code、写入失败和新授权恢复。
