# 本地身份会话与访问控制（Local Identity Session & Access Control）

一套**纯本地内存模拟**的身份、会话与访问控制能力：不依赖任何外部身份服务、
不使用真实生产凭据。目标是让**并发登录 / 凭证轮换 / 权限判定**在所有入口下
得到一致、确定且可解释的结论。

- 运行环境：Java 21、Spring Boot 3.4.x，无数据库、无外部 IdP、无消息中间件。
- 存储：`UserStore` / `SessionStore` / `AuditStore` 全部为进程内并发集合。
- 密码：仅以演示用 `SHA-256("local-demo|" + 密码)` 模拟本地凭证，禁止用于真实场景。

---

## 1. 会话与凭证生命周期

### 1.1 核心模型

| 模型 | 说明 |
| --- | --- |
| `User` | 本地用户：密码摘要、**实时可变**的角色集合与属性、启用标志 |
| `SessionInfo` | 一次登录产生一个会话；任一时刻只指向一个“当前凭证”（`currentTokenId` + 单调 `currentSerial`） |
| `TokenInfo` | 短期凭证：含 `tokenId`（可观测标识，用于日志/审计）、不透明 `secret`、`serial`、`issuedAt`、`expiresAt` 与单向状态 |
| `AuditEvent` | 只追加审计记录，序列号全局单调递增 |

凭证状态是**单向状态机**：

```
ACTIVE ──刷新轮换──▶ ROTATED   （记录 supersededBy / rotatedAt）
ACTIVE ──到达 expiresAt─▶ EXPIRED（惰性落状态，过期时刻由 expiresAt 确定）
ACTIVE ──撤销──────▶ REVOKED
```

### 1.2 登录

`POST /api/auth/login` → 校验密码（常量时间比较）与启用状态 → 新建会话并签发
`serial=1` 的短期凭证（默认 TTL 由 `app.security.token-ttl` 配置，演示值 30 秒）。

### 1.3 刷新 / 轮换（确定失效 + 并发安全）

`POST /api/auth/refresh` 的关键规则：

1. **同一会话串行化**：刷新/撤销都在“按会话 ID 分配的锁”内执行
   （`SessionStore.lockFor(sessionId)`），不同会话互不阻塞。
2. 锁内原子完成：**旧凭证置 `ROTATED` + 会话指针推进到新凭证**。因此同一会话
   任意时刻至多存在一个有效凭证；并发刷新**恰有一个成功**。
3. **旧凭证失效时机确定**：在轮换发生的同一临界区内立即失效，并记录后继凭证。
4. 会话指针只允许单调向前（`newSerial > currentSerial`），任何旧写都无法把指针
   拉回，防止“凭证静默复活”。

**两类“轮换失效”刻意区分**（测试与日志中可分别断言）：

| 场景 | 拒绝原因 `DenyReason` | 含义 |
| --- | --- | --- |
| 并发刷新中输掉竞争 | `CONCURRENTLY_ROTATED` | 该请求入锁前凭证仍 `ACTIVE`，持锁后发现已被另一次刷新抢先 |
| 事后再次重放旧凭证 | `TOKEN_ROTATED` | 凭证早已处于 `ROTATED` 的重放尝试 |

### 1.4 过期边界

边界约定为半开区间：`now < expiresAt` 有效；`now >= expiresAt`
（即 `!expiresAt.isAfter(now)`）**立即**判为过期。过期判定在访问与刷新两个入口
一致；即使状态是惰性落库，过期结论也只由 `expiresAt` 与当前时钟决定，确定可测。

---

## 2. 权限判定规则

`POST /api/access/check` 每次请求都执行“**实时校验 → 实时身份快照 → 策略评估**”，
**不缓存任何判定结果、不缓存主体角色/属性**。

1. 解析 `Authorization: Bearer <secret>`；缺失/无法识别 → `UNAUTHENTICATED`。
2. 在会话锁内复核会话与凭证状态（撤销/过期/轮换/并发失效，见下表）。
3. 实时读取用户启用状态与当前角色/属性，构造当次 `Principal` 快照。
4. 交给 `PolicyEngine` 做 RBAC + ABAC 判定。

**拒绝原因码（全部可区分）：**

| 原因 | 触发条件 | HTTP 入口（登录/刷新） |
| --- | --- | --- |
| `UNAUTHENTICATED` | 未携带凭证 / 凭证无法识别 | 401 |
| `BAD_CREDENTIALS` | 用户名或密码错误 | 401 |
| `TOKEN_EXPIRED` | 已过 `expiresAt` | 401 |
| `TOKEN_ROTATED` | 事后重放已轮换凭证 | 409 |
| `CONCURRENTLY_ROTATED` | 并发刷新竞争失败 | 409 |
| `TOKEN_REVOKED` | 凭证被撤销 | 403 |
| `SESSION_REVOKED` | 会话/凭证链被撤销 | 403 |
| `USER_DISABLED` | 用户被禁用/不存在 | 403 |
| `INSUFFICIENT_PERMISSIONS` | 已认证但策略不允许 | 访问接口以 `allowed=false` + 原因返回 |

> 访问判定接口统一返回 HTTP 200 + `{allowed, reason, basis, tokenId}`，
> 以便在同一入口完整观察所有原因；`basis` 用自然语言逐条记录每条策略
> 命中/失配依据，使结论**可解释**。

**策略评估（`PolicyEngine`）：**按注册顺序评估；资源/动作支持 `*` 通配；
策略需同时满足资源动作匹配、角色任一命中（角色集为空表示不限角色）、
全部 ABAC 条件成立才算命中。**显式 DENY 立即生效（优先于 ALLOW）**；
没有任何 ALLOW 命中即默认拒绝。

预置策略见 `DataSeeder`，例如：

- `p-admin-all`：admin 允许任意资源动作（RBAC）；
- `p-auditor-read-reports`：auditor 读 `reports/*`；
- `p-viewer-read-public`：viewer 读 `public/*`；
- `p-same-dept-docs`：主体部门 == 资源部门才能读 `docs/*`（ABAC）；
- `p-deny-audit-delete`：**任何人**（含 admin）删除 `audit/*` 显式拒绝。

预置用户：`alice/alice-pw`(admin)、`bob/bob-pw`(auditor)、
`carol/carol-pw`(viewer)、`dave/dave-pw`(被禁用)。

---

## 3. 撤销传播语义

撤销入口：`POST /api/auth/revoke`（撤销单个凭证）、
`AuthService.revokeSession(...)`、`AuthService.revokeUserSessions(...)`。

1. **即时生效、确定时限**：撤销在会话锁内把会话标记 `revoked` 并撤销当前凭证。
   判定侧零缓存，因此撤销在下一次访问/刷新时**立即**被观察到，传播延迟为 0
   （纯内存、无传播队列；“确定时限”即同一临界区提交后对后续所有请求可见）。
2. **撤销针对整条凭证链**：即便被撤销的凭证已被并发刷新轮换，会话仍被撤销、
   会话当前凭证一并撤销，避免“旧的被撤、新的还活着”。
3. **撤销 × 刷新不互相覆盖**：二者共用同一把会话锁，且锁内都会复核状态。
   - 撤销先拿锁 → 刷新看到会话已撤销，被拒（`SESSION_REVOKED`）；
   - 刷新先拿锁 → 新凭证签发成功，但撤销随后在同一把锁内撤销会话与该新凭证。
   任一交错下最终不变量：会话已撤销且**不存在残留 ACTIVE 凭证**。
4. 已撤销/已轮换凭证无法再刷新出新凭证，杜绝静默复活。

### 审计链路

登录成功/失败、凭证签发、刷新成功/拒绝、访问放行/拒绝、凭证/会话/用户级撤销
都会写一条只追加 `AuditEvent`，并通过 `AUDIT` logger 打印，日志包含
`tokenId`、`sessionId`、`userId`、拒绝 `reason` 与 `detail/basis`。
可用 `GET /api/audit` 查看全量事件（序号严格递增）。

---

## 4. 验证方法

### 4.1 构建与单元/并发测试

```bash
mvn test
```

测试位于 `src/test/java/.../auth`，不启动 Web 容器，使用可控时钟
（`MutableClock`）获得确定性结果：

| 测试类 | 覆盖内容 |
| --- | --- |
| `AuthFlowTest` | 登录签发、正常轮换、serial 单调、**旧凭证重放**=`TOKEN_ROTATED`、错误密码/禁用用户原因区分 |
| `ConcurrentRefreshTest` | 16 线程并发刷新：恰 1 成功、15 个 `CONCURRENTLY_ROTATED`、全库仅 1 个 ACTIVE 凭证 |
| `RevocationConcurrencyTest` | **撤销后访问**即时拒绝、撤销×刷新 20 轮竞态无 ACTIVE 残留/无复活、用户级撤销、审计链路顺序 |
| `ExpiryBoundaryTest` | **过期边界**：第 29 秒有效、第 30 秒（恰 `expiresAt`）即 `TOKEN_EXPIRED`；临期刷新获得完整 TTL；无凭证=未认证 |
| `AccessDecisionTest` | RBAC、ABAC 部门属性、显式 DENY 压过 admin ALLOW、默认拒绝、**实时降权即时生效**、禁用即时生效 |

测试日志中会打印每个凭证标识（`tokenId`）与判定依据（`basis` / `reason`），
满足“凭证标识 + 判定依据可在单测日志中核对”的要求。

### 4.2 HTTP 手工验证

```bash
mvn spring-boot:run            # 默认 8080，可加 --server.port=8089

# 登录
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pw"}'

# 访问判定（把 <TOKEN> 换成登录返回的 token）
curl -s -X POST localhost:8080/api/access/check \
  -H "Authorization: Bearer <TOKEN>" -H 'Content-Type: application/json' \
  -d '{"resource":"system/config","action":"write"}'

# 刷新轮换、旧凭证重放（返回 409 TOKEN_ROTATED）、撤销、审计查询
curl -s -X POST localhost:8080/api/auth/refresh -H 'Content-Type: application/json' -d '{"token":"<TOKEN>"}'
curl -s -X POST localhost:8080/api/auth/revoke  -H 'Content-Type: application/json' -d '{"token":"<TOKEN>","reason":"sign-out"}'
curl -s localhost:8080/api/audit
```

---

## 5. 设计约束与边界

- 本实现是**本地模拟**：凭证存储、会话状态、审计均为内存态，进程重启即清空，
  不得作为真实生产身份系统使用。
- 凭证 `secret` 为 256-bit 随机不透明串；日志/审计只记录 `tokenId`，不打印 secret。
- 密码“哈希”为演示用途的简单 SHA-256，非真实凭据保护方案。
