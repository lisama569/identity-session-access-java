package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.DefaultAccessControlService;
import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
import com.github.lisama569.identitysessionaccessjava.access.RoleBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.model.SessionView;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;
import com.github.lisama569.identitysessionaccessjava.store.InMemoryAuditStore;
import com.github.lisama569.identitysessionaccessjava.store.InMemorySessionStore;
import com.github.lisama569.identitysessionaccessjava.store.InMemoryUserStore;
import com.github.lisama569.identitysessionaccessjava.tests.support.MutableTimeSource;
import com.github.lisama569.identitysessionaccessjava.token.LocalHmacTokenService;
import com.github.lisama569.identitysessionaccessjava.web.dto.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话空闲超时测试：在绝对有效期之外引入“最近活跃 + 空闲上限”判定；
 * 刷新/访问成功顺延空闲窗口；空闲超时与绝对过期、撤销、轮换的原因可区分，
 * 且撤销类原因优先级稳定最高。
 */
class IdleTimeoutTest {

    private static final Logger log = LoggerFactory.getLogger(IdleTimeoutTest.class);
    private static final long TTL = 60_000L;
    private static final long IDLE = 5_000L;

    private MutableTimeSource clock;
    private DefaultAuthService auth;
    private DefaultAccessControlService access;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(1_000_000L);
        InMemoryUserStore users = new InMemoryUserStore();
        InMemorySessionStore sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuditService audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokens = new LocalHmacTokenService("test-secret");
        auth = new DefaultAuthService(users, sessionStore, tokens, hasher, audit, clock,
                TTL, 5, IDLE);
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock, IDLE);
    }

    @Test
    void idleBoundaryIsExactForAccessAndRefresh() {
        TokenResponse t = auth.login("alice", "pw");

        // 空闲边界前 1ms：访问、刷新都可用
        clock.advance(IDLE - 1);
        assertTrue(access.decide(t.token(), "profile:read", "profile").isAllowed());
        log.info("空闲边界前 credential={} 判定依据=now-lastActiveAt<idleTimeout, 访问放行",
                t.credentialId());

        // 注意：上面的访问本身是一次活动，lastActiveAt 已顺延；重新等待完整空闲窗口
        clock.advance(IDLE);
        AuthDecision denied = access.decide(t.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, denied.getReason());
        log.info("空闲边界 credential={} 判定依据=now-lastActiveAt>=idleTimeout -> "
                + "SESSION_IDLE_EXPIRED（未达绝对有效期也被拒绝）", t.credentialId());

        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex.getReason());
        log.info("空闲后刷新 credential={} 判定依据=锁内空闲判定 -> SESSION_IDLE_EXPIRED",
                ex.getCredentialId());
    }

    @Test
    void refreshAndAccessExtendIdleWindow() {
        TokenResponse t = auth.login("alice", "pw");

        // 多次在窗口内刷新：空闲窗口不断顺延，永不触顶
        TokenResponse current = t;
        for (int i = 0; i < 5; i++) {
            clock.advance(IDLE - 1);
            current = auth.refresh(current.token());
        }
        log.info("连续刷新顺延 credential={} 判定依据=每次刷新成功重置空闲窗口, version={}",
                current.credentialId(), current.version());

        // 访问通过同样顺延
        clock.advance(IDLE - 1);
        assertTrue(access.decide(current.token(), "profile:read", "profile").isAllowed());
        clock.advance(IDLE - 1);
        assertTrue(access.decide(current.token(), "profile:read", "profile").isAllowed());
        log.info("访问顺延 credential={} 判定依据=受保护访问通过即活动, 空闲窗口顺延",
                current.credentialId());

        // 停止活动超过空闲上限：即使远未到绝对有效期（TTL=60s）也被拒
        clock.advance(IDLE);
        AuthDecision denied = access.decide(current.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, denied.getReason());
        assertTrue(clock.nowMillis() < current.expiresAt(),
                "此时应远未到达绝对过期时刻");
        log.info("空闲超时 credential={} 判定依据=空闲窗口耗尽且 now<expiresAt, "
                + "拒绝原因与绝对过期相区分", current.credentialId());
    }

    @Test
    void idleReasonIsDistinctFromAbsoluteExpiry() {
        TokenResponse t = auth.login("alice", "pw");

        // 场景一：无任何活动，空闲超时先到 -> SESSION_IDLE_EXPIRED
        clock.advance(IDLE);
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(t.token(), "profile:read", "profile").getReason());
        log.info("场景一 credential={} 判定依据=空闲窗口耗尽 -> SESSION_IDLE_EXPIRED",
                t.credentialId());

        // 场景二：保持活跃（访问顺延空闲），直到凭证绝对过期 -> CREDENTIAL_EXPIRED
        TokenResponse t2 = auth.login("alice", "pw");
        while (clock.nowMillis() < t2.expiresAt()) {
            assertTrue(access.decide(t2.token(), "profile:read", "profile").isAllowed());
            clock.advance(IDLE - 1);
        }
        AuthDecision expired = access.decide(t2.token(), "profile:read", "profile");
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, expired.getReason());
        log.info("场景二 credential={} 判定依据=会话持续活跃但 now>=expiresAt -> "
                + "CREDENTIAL_EXPIRED（与空闲超时相区分）", t2.credentialId());
    }

    @Test
    void revokeBeatsIdleAndRotationReasonsStayStable() {
        // 撤销 + 空闲叠加：撤销类原因优先
        TokenResponse t1 = auth.login("alice", "pw");
        clock.advance(IDLE * 2); // 已空闲超时
        auth.revokeSession(t1.sessionId(), "admin-revoke");
        AuthDecision d1 = access.decide(t1.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_REVOKED, d1.getReason());
        AuthenticationException ex1 = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t1.token()));
        assertEquals(DenyReason.SESSION_REVOKED, ex1.getReason());
        log.info("撤销+空闲叠加 credential={} 判定依据=撤销位优先于空闲判定 -> SESSION_REVOKED",
                t1.credentialId());

        // 轮换 + 空闲叠加：旧凭证重放仍是 CREDENTIAL_ROTATED（轮换判定在访问层先于空闲？
        // 否——访问层空闲判定先于轮换；这里验证刷新路径：旧凭证在会话空闲后重放）
        TokenResponse t2 = auth.login("alice", "pw");
        TokenResponse t2b = auth.refresh(t2.token());
        clock.advance(IDLE * 2); // 会话空闲超时
        // 旧凭证（已 ROTATED）在会话空闲后重放：访问层报 SESSION_IDLE_EXPIRED 或
        // CREDENTIAL_ROTATED 均可解释，但刷新路径锁内优先级为 撤销>过期>空闲>轮换
        AuthenticationException ex2 = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t2.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex2.getReason());
        log.info("轮换+空闲叠加 credential={} 判定依据=锁内优先级 撤销>过期>空闲>轮换, "
                + "稳定报 SESSION_IDLE_EXPIRED", t2.credentialId());
        // 新凭证同样因会话空闲被拒（空闲是会话级判定）
        AuthenticationException ex3 = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t2b.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex3.getReason());

        // 凭证级撤销 + 空闲叠加：撤销类优先（会话本身未撤销，仅凭证被撤 -> CREDENTIAL_REVOKED）
        TokenResponse t3 = auth.login("alice", "pw");
        clock.advance(IDLE * 2); // 会话已空闲
        auth.revokeCredential(t3.credentialId(), "single-credential-revoke");
        assertEquals(DenyReason.CREDENTIAL_REVOKED,
                access.decide(t3.token(), "profile:read", "profile").getReason());
        AuthenticationException ex4 = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t3.token()));
        assertEquals(DenyReason.CREDENTIAL_REVOKED, ex4.getReason());
        log.info("凭证撤销+空闲叠加 credential={} 判定依据=撤销类优先于空闲 -> CREDENTIAL_REVOKED",
                t3.credentialId());
    }

    @Test
    void idleExpiredSessionDisappearsFromGovernanceView() {
        TokenResponse t = auth.login("alice", "pw");
        assertEquals(1, auth.listActiveSessions("alice").size());
        clock.advance(IDLE);
        assertTrue(auth.listActiveSessions("alice").isEmpty());
        log.info("空闲超时会话 credential={} 判定依据=治理视图只含活跃会话, 空闲超时即不再列出",
                t.credentialId());
    }

    /**
     * 默认入口（application.properties / 服务层默认常量）下空闲超时必须可达：
     * 默认空闲窗口（10 分钟）严格短于默认凭证 TTL（15 分钟），因此不做任何活动时，
     * 空闲先于绝对过期发生，访问与刷新都应稳定给出 SESSION_IDLE_EXPIRED。
     */
    @Test
    void defaultConstantsMakeIdleReachableWithoutExtraConfiguration() {
        assertEquals(600_000L, DefaultAuthService.DEFAULT_IDLE_TIMEOUT_MILLIS,
                "默认空闲窗口应为 10 分钟");
        assertTrue(DefaultAuthService.DEFAULT_IDLE_TIMEOUT_MILLIS
                        < DefaultAuthService.DEFAULT_TTL_MILLIS,
                "默认空闲窗口必须严格短于默认凭证 TTL，否则默认入口下空闲超时不可达");

        MutableTimeSource defaultClock = new MutableTimeSource(1_000_000L);
        InMemoryUserStore defaultUsers = new InMemoryUserStore();
        InMemorySessionStore defaultSessions = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        defaultUsers.save(new UserAccount("u-default", "alice", hasher.hash("pw", "salt"),
                "salt", Set.of("USER"), Map.of(), true));
        DefaultAuditService defaultAudit = new DefaultAuditService(new InMemoryAuditStore(),
                defaultClock);
        LocalHmacTokenService defaultTokens = new LocalHmacTokenService("test-secret");
        // 兼容构造：即“不额外调整任何配置”的默认入口（TTL 与空闲均取默认常量）
        DefaultAuthService defaultAuth = new DefaultAuthService(defaultUsers, defaultSessions,
                defaultTokens, hasher, defaultAudit, defaultClock,
                DefaultAuthService.DEFAULT_TTL_MILLIS);
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        DefaultAccessControlService defaultAccess = new DefaultAccessControlService(defaultTokens,
                defaultSessions, defaultUsers, registry, defaultAudit, defaultClock);

        TokenResponse t = defaultAuth.login("alice", "pw");
        // 不做任何操作，等过默认空闲窗口（10 分钟），但远未到默认绝对有效期（15 分钟）
        defaultClock.advance(DefaultAuthService.DEFAULT_IDLE_TIMEOUT_MILLIS);
        assertTrue(defaultClock.nowMillis() < t.expiresAt(),
                "此时不应到达凭证绝对有效期");

        AuthDecision deniedAccess = defaultAccess.decide(t.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, deniedAccess.getReason());
        AuthenticationException deniedRefresh = assertThrows(AuthenticationException.class,
                () -> defaultAuth.refresh(t.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, deniedRefresh.getReason());
        log.info("默认入口空闲超时 credential={} 判定依据=默认空闲窗口 10min < 默认 TTL 15min, "
                + "访问/刷新均 SESSION_IDLE_EXPIRED", t.credentialId());
    }

    /** 边界相等：now - lastActiveAt 恰好等于空闲窗口即超时；边界之前 1ms 仍可用（覆盖刷新入口）。 */
    @Test
    void idleBoundaryEqualityAppliesToRefreshAndAccess() {
        TokenResponse t = auth.login("alice", "pw");

        // 刷新入口：边界前 1ms 仍可成功（成功后 lastActiveAt 顺延）
        clock.advance(IDLE - 1);
        TokenResponse t2 = auth.refresh(t.token());

        // 恰好到达空闲窗口边界（含相等）：访问与刷新都拒绝
        clock.advance(IDLE);
        AuthDecision denied = access.decide(t2.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, denied.getReason());
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t2.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex.getReason());
        assertEquals(t2.credentialId(), ex.getCredentialId());
        log.info("边界相等（now-lastActiveAt==idleTimeout）credential={} -> SESSION_IDLE_EXPIRED",
                t2.credentialId());

        // 再越过窗口 1ms，结论不变
        clock.advance(1);
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(t2.token(), "profile:read", "profile").getReason());
    }

    /** 长期无活动但未到绝对有效期：访问与刷新两个入口结论一致，且重复判定不复活。 */
    @Test
    void longInactivityBeforeAbsoluteExpiryDeniesBothEntriesConsistently() {
        TokenResponse t = auth.login("alice", "pw");
        clock.advance(IDLE + 10_000L); // 远超空闲窗口，但距 TTL（60s）尚远
        assertTrue(clock.nowMillis() < t.expiresAt());

        for (int i = 0; i < 3; i++) {
            AuthDecision d = access.decide(t.token(), "profile:read", "profile");
            assertEquals(DenyReason.SESSION_IDLE_EXPIRED, d.getReason());
            AuthenticationException ex = assertThrows(AuthenticationException.class,
                    () -> auth.refresh(t.token()));
            assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex.getReason());
        }
        // 治理视图中不再出现，且会话内其它凭证（轮换后的新凭证）同样不能复活该会话
        assertTrue(auth.listActiveSessions("alice").isEmpty());
        log.info("长期空闲双入口一致 credential={} 判定依据=访问/刷新锁内与实时判定同一优先级, "
                + "重复判定不复活", t.credentialId());
    }

    /** 同账号多个会话空闲互不影响；一个空闲超时不波及其它会话。 */
    @Test
    void idleTimeoutOfOneSessionDoesNotAffectOtherDevices() {
        TokenResponse s1 = auth.login("alice", "pw");
        clock.advance(100);
        TokenResponse s2 = auth.login("alice", "pw");

        // s1 空闲到超时；期间 s2 一直活跃
        clock.advance(IDLE - 100);
        assertTrue(access.decide(s2.token(), "profile:read", "profile").isAllowed()); // s2 顺延
        clock.advance(100); // s1 距上次活动恰好 IDLE；s2 刚活动过
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(s1.token(), "profile:read", "profile").getReason());
        assertTrue(access.decide(s2.token(), "profile:read", "profile").isAllowed());
        TokenResponse s2b = auth.refresh(s2.token());
        assertTrue(access.decide(s2b.token(), "profile:read", "profile").isAllowed());

        List<SessionView> views = auth.listActiveSessions("alice");
        assertEquals(1, views.size());
        assertEquals(s2.sessionId(), views.get(0).sessionId());
        log.info("多设备空闲隔离 session1={} 已空闲超时, session2={} 不受影响",
                s1.sessionId(), s2.sessionId());
    }

    /** 空闲超时 + 容量淘汰叠加：被淘汰后原因稳定为撤销类（SESSION_CAPACITY_EVICTED）。 */
    @Test
    void capacityEvictionBeatsIdleReasonStably() {
        // 局部环境：容量上限 2、空闲窗口 IDLE；auth 与 access 共享同一套存储
        InMemoryUserStore users2 = new InMemoryUserStore();
        InMemorySessionStore sessions2 = new InMemorySessionStore();
        PasswordHasher hasher2 = new PasswordHasher();
        users2.save(new UserAccount("u-1", "alice", hasher2.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuditService audit2 = new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokens2 = new LocalHmacTokenService("test-secret-2");
        DefaultAuthService auth2 = new DefaultAuthService(users2, sessions2, tokens2, hasher2,
                audit2, clock, TTL, 2, IDLE);
        PolicyRegistry registry2 = new PolicyRegistry();
        registry2.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        DefaultAccessControlService access2 = new DefaultAccessControlService(tokens2, sessions2,
                users2, registry2, audit2, clock, IDLE);

        TokenResponse a = auth2.login("alice", "pw");
        clock.advance(100);
        TokenResponse b = auth2.login("alice", "pw");
        // a 不再活动；b 在中途活动一次。最终 a 已空闲超时，而 b 仍在空闲窗口内
        clock.advance(IDLE / 2);
        assertTrue(access2.decide(b.token(), "profile:read", "profile").isAllowed());
        clock.advance(IDLE / 2 + 1); // 越过 a 的空闲边界，但 b 刚顺延过
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access2.decide(a.token(), "profile:read", "profile").getReason());
        assertTrue(access2.decide(b.token(), "profile:read", "profile").isAllowed());
        // 再登录触发容量淘汰：a 虽已空闲，仍会被容量逻辑结束（撤销类别 CAPACITY）
        TokenResponse c = auth2.login("alice", "pw");
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED,
                access2.decide(a.token(), "profile:read", "profile").getReason());
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth2.refresh(a.token()));
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, ex.getReason());
        // 存活会话不受影响
        assertTrue(access2.decide(b.token(), "profile:read", "profile").isAllowed());
        assertTrue(access2.decide(c.token(), "profile:read", "profile").isAllowed());
        // 已被容量结束的会话再被“重复撤销”，首次原因（容量类）不被覆盖
        auth2.revokeSession(a.sessionId(), "late-explicit-revoke");
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED,
                access2.decide(a.token(), "profile:read", "profile").getReason());
        log.info("空闲+容量叠加 credential={} 判定依据=撤销类优先, 稳定 SESSION_CAPACITY_EVICTED",
                a.credentialId());
    }

    /** 空闲会话已轮换的旧凭证也不能复活：旧凭证与当前凭证双双被会话级空闲判定拒绝。 */
    @Test
    void idleSessionCannotBeRevivedByOldOrRotatedCredential() {
        TokenResponse first = auth.login("alice", "pw");
        clock.advance(100);
        TokenResponse current = auth.refresh(first.token());
        clock.advance(IDLE);

        // 旧凭证（ROTATED）：刷新与访问都不能复活会话
        AuthenticationException oldRefresh = assertThrows(AuthenticationException.class,
                () -> auth.refresh(first.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, oldRefresh.getReason());
        // 当前凭证同样被拒
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(current.token(), "profile:read", "profile").getReason());
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(first.token(), "profile:read", "profile").getReason());
        // 时间继续走也不会自行恢复
        clock.advance(IDLE);
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(current.token(), "profile:read", "profile").getReason());
        log.info("空闲会话不可复活 old={} current={} 判定依据=空闲为会话级终态, 旧/新凭证同拒",
                first.credentialId(), current.credentialId());
    }
}
