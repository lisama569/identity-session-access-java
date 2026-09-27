# 本地身份会话与访问控制（identity-session-access）

一套**完全本地化**的身份会话与访问控制实现：用内存存储模拟账户、凭证、会话与审计数据，
不依赖任何外部身份服务，也不使用真实凭据体系（口令仅为本地 salt + SHA-256 演示数据，
凭证为本地 HMAC-SHA256 签名的不透明令牌）。

目标：让**并发登录刷新、凭证轮换、权限判定、撤销传播**在所有入口（服务层直连、HTTP
控制器、不同 URL）下得到**一致且可解释**的结论。

---

## 1. 会话与凭证生命周期

```
登录 login
  └─ 账号锁内原子事务：
       建会话 SESSION（v=1）+ 首张凭证 CREDENTIAL(ACTIVE, now ~ now+TTL)
       容量淘汰：账号活跃会话超上限时，最久未活跃会话被结束（RevokeKind=CAPACITY）
刷新 refresh(CURRENT)
  └─ 会话锁内原子事务：
       旧凭证 ACTIVE -> ROTATED（replacedBy = 新凭证）   ← 旧凭证在“事务提交之时”立即失效
       新凭证入库 ACTIVE
       会话当前指针 currentCredentialId 切到新凭证（v+1）
       会话 lastActiveAt 顺延到 now（刷新成功即活动，重置空闲窗口）
撤销 revokeSession / revokeCredential
  └─ 会话撤销（根撤销）：会话 revoked=true，名下所有凭证 -> REVOKED
     凭证撤销：仅该凭证 -> REVOKED
过期
  └─ 惰性判定：now >= expiresAt 即 EXPIRED（过期边界含等于），不做后台扫描
空闲超时
  └─ 惰性判定：now - lastActiveAt >= idleTimeout 即 SESSION_IDLE_EXPIRED；
     刷新成功 / 受保护访问通过都会顺延 lastActiveAt
```

凭证有四种互斥终态：`ACTIVE` / `ROTATED` / `EXPIRED` / `REVOKED`。

### 1.0 多设备会话治理（按账号查看 + 定向结束）

同一账号可在多台设备上同时登录，每台设备一个独立会话。治理能力：

- **查看**：`GET /api/auth/accounts/{username}/sessions`（或服务层
  `AuthService.listActiveSessions(username)`）列出该账号名下**当前活跃**会话
  （未撤销、未绝对过期、未空闲超时），每个会话可见：签发时间 `issuedAt`、
  最近活跃时间 `lastActiveAt`、当前凭证代次 `currentVersion`、当前凭证标识与过期时刻。
- **定向结束**：`POST /api/auth/sessions/{sessionId}/revoke` 只结束指定会话
  （模拟“踢掉其中一台设备”）。被结束的会话立即失效（撤销在会话锁内提交，
  下一次访问/刷新即拒），同账号其余会话照常可用；已结束会话是终态，
  刷新、等待、重复撤销都不能将其重新激活。

### 1.0.1 账号级会话容量控制

- 配置：`identity.session.max-active-sessions-per-account`，**默认 5**。
- 规则：登录建会话时，若该账号活跃会话数超出上限，按 **lastActiveAt 升序、
  最久未活跃者先出局** 自动结束最早的那批会话（刚登录的新会话绝不参与淘汰）。
- 原子性：建会话与淘汰在**账号级锁**内一次完成。并发登录、并发登录与刷新/淘汰
  竞争收敛后，该账号活跃会话数不超过上限；被淘汰会话名下的全部凭证（含并发
  刷新刚赢出的新凭证）在同一事务中失效，不会出现“被淘汰凭证仍可用”、
  “多会话共用一张有效凭证”或“凭证静默复活”。
- 原因可区分：因容量被结束后再次使用其凭证，拒绝原因为
  **`SESSION_CAPACITY_EVICTED`**，与 `UNAUTHENTICATED` / `CREDENTIAL_EXPIRED` /
  `SESSION_REVOKED`（主动撤销）互相区分。

### 1.0.2 会话空闲超时

- 配置：`identity.session.idle-timeout-millis`，**默认 1800000（30 分钟）**。
- 判定：在既有绝对有效期（`expiresAt`）之外，再检查
  `now - lastActiveAt >= idleTimeoutMillis`（含边界）即视为空闲超时。
- 活动顺延：**刷新成功**与**受保护访问通过**都算一次活动，会把
  `lastActiveAt` 顺延到当前时刻（单调推进，并发安全）。
- 效果：长时间没有任何活动的会话，即使远未到绝对有效期，下一次访问或刷新
  也会被拒绝，原因为 **`SESSION_IDLE_EXPIRED`**，与 `CREDENTIAL_EXPIRED`
  （绝对过期）互相区分。空闲超时是会话级判定，对该会话当前与已轮换的凭证同样生效。

### 1.0.3 拒绝原因优先级（稳定顺序）

撤销/轮换/空闲/容量叠加时，判定顺序即优先级（高 → 低）：

1. 撤销类：`SESSION_REVOKED` / `SESSION_CAPACITY_EVICTED` / `CREDENTIAL_REVOKED`
   （**撤销类永远优先**，含优先于过期与空闲）
2. 绝对过期：`CREDENTIAL_EXPIRED`（now ≥ expiresAt）
3. 空闲超时：`SESSION_IDLE_EXPIRED`（now − lastActiveAt ≥ idleTimeout）
4. 轮换/并发：`CREDENTIAL_ROTATED` / `CONCURRENT_REFRESH_CONFLICT`

刷新路径的锁内判定与访问路径的实时判定遵循同一顺序，两个入口结论一致。

### 1.1 轮换后旧凭证何时失效？

**确定时机：刷新原子事务提交之时。** “旧凭证置 ROTATED、新凭证入库、会话指针切换”
三步在同一把会话级锁内一次完成，对外是一次原子切换。事务一旦返回成功，旧凭证在
后续任何刷新或访问中都不可能被接受。

### 1.2 并发刷新为何不会产生两个有效凭证？

- 每个会话一把锁（`ConcurrentHashMap.computeIfAbsent` 分配，锁对象永不替换）。
- 刷新的权威判定（撤销位 → 过期 → 是否会话当前指针）**全部在会话锁内**完成，
  锁外不做任何会影响结论的状态分类。
- 只有会话“当前指针”指向的凭证可以赢得轮换；赢家提交后，其余竞争者：
  - 凭证若仍 ACTIVE，在锁内立即被收敛为 ROTATED（不会以 ACTIVE 残留）；
  - 返回确定的失败结论（见下）。
- 不变量（有测试守护）：N 个线程用同一张凭证并发刷新 ⇒ **恰有 1 个赢家**，
  会话名下**恰有 1 张 ACTIVE 凭证**。

### 1.3 过期 / 已轮换 / 并发失效如何区分？

| 场景 | 判定依据（锁内权威状态） | 拒绝原因 `DenyReason` |
|---|---|---|
| 凭证过了有效期（含边界 now==expiresAt） | `now >= expiresAt` | `CREDENTIAL_EXPIRED` |
| 上一轮换事务结束后，再拿旧凭证来用 | 非当前指针，且不在并发批次中，状态 ROTATED | `CREDENTIAL_ROTATED` |
| 同一批并发刷新中的竞争失败者 | 赢家提交轮换时已在“在途刷新批次”中登记，或入锁时批次仍有同伴 | `CONCURRENT_REFRESH_CONFLICT` |

“并发批次”是与**时间窗口、线程调度无关**的确定性机制：一批需要并发执行的刷新
先各自调用 `AuthService.joinRefreshBatch(token)` 登记（屏障前完成），再同时调用
`refresh()`；赢家在锁内快照同批竞争者写入“并发输家名单”，名单在整个批次结束
（所有在途请求退出）时才清除。因此：

- 同批并发 ⇒ 稳定报 `CONCURRENT_REFRESH_CONFLICT`；
- 批次结束后旧凭证再来 ⇒ 稳定报 `CREDENTIAL_ROTATED`。

普通单请求路径无需显式 join/leave，`refresh()` 会自动入批/离批。

---

## 2. 权限判定规则

统一入口：`AccessControlService.decide(token, permission, resource)`。
**所有**受保护资源（profile / reports / admin / engineering / 通用 check 入口）
都调用它；过滤器只负责提取 Bearer 令牌，不做放行决策。

判定顺序即拒绝原因优先级（高 → 低）：

1. `UNAUTHENTICATED`：未携带令牌 / 格式非法 / 签名无效
2. `CREDENTIAL_NOT_FOUND`：签名合法但凭证标识不存在
3. `SESSION_NOT_FOUND`：凭证所属会话不存在
4. `SESSION_REVOKED` / `SESSION_CAPACITY_EVICTED` / `CREDENTIAL_REVOKED`：**撤销类优先于一切**（优先于过期、空闲、轮换；容量淘汰与主动撤销可区分）
5. `CREDENTIAL_EXPIRED`：过期（边界 now ≥ expiresAt）
6. `SESSION_IDLE_EXPIRED`：会话空闲超时（与绝对过期相区分）
7. `CREDENTIAL_ROTATED`：凭证已轮换
8. `CONCURRENT_REFRESH_CONFLICT`：非当前凭证（并发竞争失败）
9. `USER_DISABLED`：账户被停用 / 移除
10. `PERMISSION_DENIED`：已认证但无权限

授权模型：

- **RBAC**：`RoleBasedPolicy(permission, allowRoles)`，命中任一角色即显式允许。
- **ABAC**：`AttributeBasedPolicy(permission, (account, resource) -> …)`，
  基于账户属性（如 `dept`、`level`）与资源做谓词判定。
- **默认拒绝**：没有任何策略对本次请求显式允许 ⇒ `PERMISSION_DENIED`。

### 2.1 为什么撤销/降权不会因缓存或并发放行？

判定链路**不缓存身份、不缓存结论**：每次都实时读取存储中的会话撤销位、凭证状态与
账户对象（账户角色/属性/启用位均为 volatile/实时读取）。因此：

- 撤销在会话锁内提交后，下一次访问/刷新立即被拒；
- 管理端改角色、改属性、停用账户，下一次判定立即按新身份执行。

### 2.2 演示账户与权限（见 `DemoDataInitializer`）

| 用户 | 口令 | 角色 | 属性 | 可访问 |
|---|---|---|---|---|
| alice | alice-pass | USER | dept=engineering, level=5 | profile；reports(ABAC, level≥5)；engineering |
| bob | bob-pass | USER, AUDITOR | dept=finance, level=3 | profile；reports |
| admin | admin-pass | ADMIN (+USER,AUDITOR) | dept=it, level=9 | 全部 |
| carol | carol-pass | USER | — | **已停用**（登录即 `USER_DISABLED`） |

权限点：`profile:read`、`reports:read`、`admin:read`、`engineering:read`。

---

## 3. 撤销传播语义

- **传播方式：同步、即时、读时生效（无传播延迟窗口）。** 撤销动作在会话锁内把
  `session.revoked` 置位并把名下凭证置 `REVOKED`，提交完成后，状态对所有后续
  判定立即可见。需求中的“确定时限内失效”在本实现中即“撤销事务提交之时”
  （上限为一次锁竞争，通常为微秒级）。
- **根撤销连带**：会话撤销会连带其全部凭证，包括已轮换的旧凭证与并发刷新赢家
  刚签发的新凭证。
- **并发撤销 vs 刷新**：二者争用同一把会话锁，串行化执行，可能的交错只有两种且
  都安全：
  - 刷新先提交、撤销后提交 ⇒ 新凭证随即随会话一起 REVOKED，不可用；
  - 撤销先提交 ⇒ 刷新在锁内看到撤销位，返回 `SESSION_REVOKED`，不产生新凭证。
  不会出现“撤销被刷新覆盖”或“新凭证静默复活”。
- **重复撤销幂等**：`markRevoked` 保留**首次**撤销原因与时刻，不会互相覆盖。
- 每次撤销（会话级/凭证级）都写审计：`SESSION_REVOKED` + 每张连带凭证一条
  `CREDENTIAL_REVOKED`。

---

## 4. 审计链路

`AuditService` 对每个关键判定做两件事：追加到本地顺序存储（事件 id 严格递增、
只增不改），并打印一条含**凭证标识与判定依据**的日志（凭证标识在日志中做前缀
脱敏）。事件类型覆盖：

`LOGIN_SUCCESS / LOGIN_FAILURE / REFRESH_SUCCESS / REFRESH_FAILURE /
ACCESS_ALLOWED / ACCESS_DENIED / SESSION_REVOKED / CREDENTIAL_REVOKED`

查询接口：

- `GET /api/audit/events` 全量
- `GET /api/audit/events/session/{sessionId}` 按会话串联完整生命周期
- `GET /api/audit/events/subject/{subject}` 按主体

每条拒绝事件都带 `DenyReason`，因此“为什么被拒”在审计里与接口返回完全一致、可追溯。

---

## 5. HTTP API

| 方法与路径 | 说明 |
|---|---|
| `POST /api/auth/login` | 登录，返回短期凭证（token / sessionId / credentialId / version / expiresAt） |
| `POST /api/auth/refresh` | 凭 `Authorization: Bearer` 刷新轮换；成功后旧凭证立即失效 |
| `GET /api/auth/accounts/{username}/sessions` | 按账号查看当前活跃会话（签发时间 / 最近活跃时间 / 凭证代次） |
| `POST /api/auth/sessions/{id}/revoke` | 撤销会话（根撤销，body 可选 `{"reason":"…"}`）；也用于定向结束某一台设备的会话 |
| `POST /api/auth/credentials/{id}/revoke` | 撤销单张凭证 |
| `GET /api/resources/profile` | 需要 `profile:read` |
| `GET /api/resources/reports?resource=finance-reports` | 需要 `reports:read` |
| `GET /api/resources/admin` | 需要 `admin:read` |
| `GET /api/resources/engineering` | 需要 `engineering:read` |
| `GET /api/resources/check/{permission}?resource=…` | 不抛异常，回显完整可解释判定（allowed/reason/credentialId/…） |
| `GET /api/audit/events…` | 审计查询 |

状态码约定：认证类问题（含过期/轮换/并发失效/撤销）为 **401**，权限不足为 **403**；
错误体含机器可读的 `reason`（`DenyReason` 枚举名）与人类可读 `message`。

---

## 6. 验证方法

```bash
# 全量测试（104 个用例，含并发重复压测）
mvn test

# 仅并发刷新（16 线程 × 20 次重复 + 2 线程确定性用例）
mvn test -Dtest=ConcurrentRefreshTest

# 撤销与刷新并发（30 次重复）
mvn test -Dtest=RevokeConcurrencyTest

# 多设备会话治理（列表 / 定向结束 / 不可复活）
mvn test -Dtest=SessionGovernanceTest

# 会话容量（LRU 淘汰、原因可区分、并发登录与淘汰竞争收敛，含重复压测）
mvn test -Dtest=SessionCapacityTest

# 空闲超时（边界精确、刷新/访问顺延、与绝对过期及撤销的优先级）
mvn test -Dtest=IdleTimeoutTest

# 过期边界 / 轮换重放 / 撤销后访问 / RBAC+ABAC / 降权即时生效
mvn test -Dtest=AuthServiceTest,AccessControlServiceTest,AuditTrailTest

# HTTP 端到端（各入口一致性、轮换、撤销传播、会话治理入口）
mvn test -Dtest=WebApiIntegrationTest
```

测试覆盖与需求对应：

| 需求点 | 测试 |
|---|---|
| 并发刷新恰一个赢家、不产生两个有效凭证 | `ConcurrentRefreshTest.concurrentRefreshProducesExactlyOneWinner`（×20） |
| 并发失效 vs 事后重放可区分 | `ConcurrentRefreshTest.loserTokenIsNotAcceptedLaterAndReplayIsRotated`、`AuthServiceTest.rotationImmediatelyInvalidatesOldCredential` |
| 旧凭证重放被拒 | 同上 + `AccessControlServiceTest.rotatedCredentialReplayIsDeniedAsRotated` |
| 过期边界（now==expiresAt） | `AuthServiceTest.expiryBoundaryIsExactAndReasonsDifferFromRotation`、`AccessControlServiceTest.expiredCredentialIsDeniedAtBoundary` |
| 撤销后访问/刷新即时失败 | `AuthServiceTest.revoked*`、`AccessControlServiceTest.sessionAndCredentialRevocationTakeEffectImmediately`、`WebApiIntegrationTest.refreshRotationAndSessionRevocationPropagateEndToEnd` |
| 撤销/刷新并发不覆盖、不复活 | `RevokeConcurrencyTest.revokeRacingRefreshCanNeverProduceUsableCredential`（×30）、`repeatedRevokeKeepsFirstReasonNoStateOverwrite` |
| 未认证/过期/轮换/撤销/权限不足原因可区分 | `AccessControlServiceTest`、`WebApiIntegrationTest` |
| RBAC + ABAC、默认拒绝、降权/停用即时生效 | `AccessControlServiceTest.roleAndAttributePoliciesAndDefaultDeny`、`demotionAndDisableTakeEffectOnNextDecisionWithoutCache` |
| 登录/刷新/拒绝/撤销审计留痕、可按会话追溯 | `AuditTrailTest` |
| 按账号列出活跃会话（签发/活跃时间/代次）、定向结束互不影响、结束后不可复活 | `SessionGovernanceTest`、`WebApiIntegrationTest.accountSessionGovernanceEndToEnd` |
| 容量上限、最久未活跃先出局、淘汰原因可区分 | `SessionCapacityTest.capacityEvictsLeastRecentlyActiveFirst`、`evictionReasonIsDistinctFromOtherDenyReasons` |
| 并发登录/刷新与淘汰竞争收敛后不超上限、被淘汰凭证不可用 | `SessionCapacityTest.concurrentLoginsConvergeToCapacityLimit`（×10）、`refreshRacingEvictionNeverLeavesUsableEvictedCredential`（×10） |
| 空闲超时边界、刷新/访问顺延、与绝对过期区分、撤销优先级稳定 | `IdleTimeoutTest` |
| 日志打印凭证标识与判定依据 | 全部用例（`DECIDE … verdict=… basis=…` 与 `AUDIT …` 日志） |

过期边界测试使用可注入的 `MutableTimeSource`（所有过期判定只依赖该时钟，
生产环境为 `SystemTimeSource`），可把时间精确推进到过期时刻。

## 7. 手工冒烟

```bash
mvn spring-boot:run
# 另一个终端：
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'
# 用返回 token：
curl -s localhost:8080/api/resources/profile -H "Authorization: Bearer <token>"
curl -s -X POST localhost:8080/api/auth/refresh -H "Authorization: Bearer <token>"
# 旧 token 再访问 -> 401 CREDENTIAL_ROTATED

# 多设备治理：再登录一两次后查看 alice 的活跃会话
curl -s localhost:8080/api/auth/accounts/alice/sessions
# 定向结束其中一个会话（踢掉一台设备）
curl -s -X POST localhost:8080/api/auth/sessions/<sessionId>/revoke \
  -H 'Content-Type: application/json' -d '{"reason":"kick-one-device"}'
# 被结束会话的 token 再访问 -> 401 SESSION_REVOKED；其余会话不受影响
```

## 7.1 兼容范围

- 新能力全部走既有入口风格：错误体仍是 `{allowed, reason, message, ...}`，
  认证类拒绝 401、权限不足 403；新增拒绝原因仅为 `DenyReason` 枚举新增
  `SESSION_CAPACITY_EVICTED` 与 `SESSION_IDLE_EXPIRED` 两个取值，未改变任何既有取值语义。
- 既有行为不变：登录/刷新/撤销/访问判定的旧有用例（并发刷新、旧凭证重放、
  撤销即时生效、RBAC/ABAC）全部保持原结论，由既有测试守护。
- 容量与空闲超时通过 `application.properties` 配置（默认值见 1.0.1 / 1.0.2），
  不依赖外部组件；服务层构造器保留兼容重载，既有直连代码无需修改。
- 空闲判定依赖可注入时钟 `TimeSource`，测试中用 `MutableTimeSource` 精确推进，
  不依赖特定线程时序即可稳定复现。

## 8. 关键代码索引

- 并发原子性：`store/InMemorySessionStore.java`（会话锁、原子轮换、批次名单、
  账号锁内容量淘汰、锁内空闲判定）
- 失败原因映射：`auth/DefaultAuthService.java`（刷新、容量淘汰审计、会话治理视图）、
  `access/DefaultAccessControlService.java`（访问判定优先级、空闲判定、活动顺延）
- 状态机：`model/CredentialState.java`、`model/SessionInfo.java`（lastActiveAt /
  RevokeKind）、`model/DenyReason.java`、`model/RevokeKind.java`、`model/SessionView.java`
- 本地令牌：`token/LocalHmacTokenService.java`
- 时钟：`time/TimeSource.java`（`SystemTimeSource` / 测试用 `MutableTimeSource`）
