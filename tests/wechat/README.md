# 微信登录与手机号绑定

扩展基于官方 Casdoor v4.26.0，仅支持同一组织内的小程序、公众号按可信 UnionID 登录同一账号，以及小程序授权手机号绑定。用户表沿用原版，通用用户 API 保持原生语义，无 UnionID 的 OpenID 查找和持久化沿用原版。UnionID 仅查询原生微信字段及已有 `properties.wechatUnionId`；小程序保留原生 OpenID 存储。无 UnionID 时不增加 AppID 前缀或别名规则。原生 `WeChat` 字段只保存一个 OpenID：小程序补齐 UnionID 后继续保存小程序 OpenID；后续公众号若缺失 UnionID，仍只按该原生字段查找，不承诺跨渠道缺失 UnionID 时的同人识别。

公众号扫码回调通过该公众号凭据查询微信用户信息；需有 `cgi-bin/user/info` 权限并与小程序绑定同一微信开放平台。回调保留可信 OpenID；微信返回 UnionID 时优先按 UnionID 查找，未匹配时沿用原生 OpenID 查找并补齐 UnionID。查询失败或返回不匹配的 OpenID 时拒绝本次回调。token 与用户信息查询均使用 10 秒超时。

有 UnionID 的首次登录通过 MySQL advisory lock 防止跨进程重复建号；锁仅覆盖同一数据库、组织、UnionID，使用临时独立连接，退出登录流程时关闭连接释放。无 UnionID 不加锁。本扩展的 UnionID 登录要求 MySQL；不自动合并已存在的重复账号。

`Properties` 须保留原生仅管理员修改的配置。局部用户更新复制 Properties map，确保原生权限检查比较的是更新前后的两个值，防止本人伪造用于登录匹配的 UnionID；不新增权限框架。

`POST /api/login/oauth/member-phone` 由服务端调用，使用应用 Basic 凭据，并提交 `access_token`、该应用配置的小程序 `app_id` 和微信 `getPhoneNumber` 授权 `code`。仅更新有效访问令牌所属账号，复用原生 `GetPhoneNumber`、地区解析、手机号规范化与唯一性规则、Hash 和更新时间生成。微信换号完成后，在同一事务内复核原账号主体、令牌有效期与撤销状态、账号禁用与删除状态，再校验手机号并写入；同一组织的绑定通过组织行锁串行提交。不新增 `phone:write` scope。Basic 凭据必须保存在服务端。

成功返回 `{"phoneBound":true}`；输入无效或手机号已被本组织其他账号使用、令牌无效、未配置的小程序分别返回 400、401、403；微信或数据库失败返回 503。微信 code 是一次性的，换号后校验或数据库写入失败须重新授权新 code。新 code 验证出已经绑定的手机号时正常返回成功，消费过的 code 仍由微信拒绝。Hash 配置读取和写入共用绑定事务的连接，配置读取完成后再复核令牌有效期。

## 回归验证

测试使用真实 Casdoor HTTP、真实独立 MySQL，以及模拟微信响应，不代替真人微信授权验收。`CASDOOR_WECHAT_TEST_DSN` 必须指向回环 IP 的独立 MySQL 实例且不包含库名；测试创建 `casdoor_probe`。

```sh
go test ./tests/wechat ./idp -run 'TestWechat|TestOfficialAccount|TestResolveWechatOfficialAccountIdentity' -count=1 -v
go test -race ./tests/wechat ./idp -run 'TestWechat|TestOfficialAccount|TestResolveWechatOfficialAccountIdentity' -count=1
go vet ./tests/wechat ./controllers ./object ./idp
go build .
```

未提供 DSN 时数据库测试跳过。`TestWechatProcessHelper` 由 `TestWechatUnionIDAcrossProcesses` 实际启动两次，`TestWechatMemberPhoneSingleConnectionHelper` 由单连接绑定测试启动，单独调用时跳过。测试覆盖用户表原生结构、两种注册顺序、并发注册、两种渠道 UnionID 补齐及同渠道有/无 UnionID 往返、无 UnionID 原生行为、公众号两步请求超时、手机号持久化与 Hash/更新时间、原生规范化与唯一性一致性、并发争用手机号、换号期间用户名复用/封禁/删除/撤销/过期、元数据读取期间过期、单连接池、新 code 绑定相同手机号、错误令牌、错误应用、消费 code、写入失败和新授权恢复。
