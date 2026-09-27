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
}
