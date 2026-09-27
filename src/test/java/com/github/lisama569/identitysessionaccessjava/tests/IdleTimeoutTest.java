package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.DefaultAccessControlService;
import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
import com.github.lisama569.identitysessionaccessjava.access.RoleBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
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
 * 会话空闲超时测试：空闲边界精确、刷新/访问顺延空闲窗口、
 * 与绝对过期可区分、与撤销/轮换/容量淘汰叠加时优先级稳定（终止类优先）。
 */
class IdleTimeoutTest {

    private static final Logger log = LoggerFactory.getLogger(IdleTimeoutTest.class);
    private static final long TTL = 60_000L;
    private static final long IDLE = 10_000L;

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
        registry.register(new RoleBasedPolicy("admin:read", Set.of("ADMIN")));
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock, IDLE);
    }

    @Test
    void idleBoundaryIsExactAndDistinctFromAbsoluteExpiry() {
        TokenResponse t = auth.login("alice", "pw");

        // 空闲边界前 1ms：刷新成功（同时顺延空闲窗口）
        clock.advance(IDLE - 1);
        TokenResponse t2 = auth.refresh(t.token());
        log.info("空闲边界前1ms credentialId={} 判定依据=now<lastActiveAt+idle, 刷新成功 v{}",
                t2.credentialId(), t2.version());

        // 恰在空闲边界（now == lastActiveAt + IDLE）：拒绝，原因是空闲超时而非绝对过期
        clock.advance(IDLE);
        AuthenticationException idle = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t2.token()));
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT, idle.getReason());
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT,
                access.decide(t2.token(), "profile:read", "p").getReason());
        log.info("空闲边界 credentialId={} 判定依据=now==lastActiveAt+idle -> SESSION_IDLE_TIMEOUT"
                + "（此时远未到绝对有效期 {}ms）", t2.credentialId(), TTL);

        // 空闲超时后不会复活
        clock.advance(5_000);
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT,
                access.decide(t2.token(), "profile:read", "p").getReason());

        // 对照：关闭空闲判定的实例上，同一时间推进只产生绝对过期原因
        InMemoryUserStore users2 = new InMemoryUserStore();
        PasswordHasher hasher = new PasswordHasher();
        users2.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuthService noIdleAuth = new DefaultAuthService(users2,
                new InMemorySessionStore(), new LocalHmacTokenService("test-secret"), hasher,
                new DefaultAuditService(new InMemoryAuditStore(), clock), clock,
                TTL, 5, 0 /* 关闭空闲判定 */);
        TokenResponse n = noIdleAuth.login("alice", "pw");
        clock.advance(TTL);
        AuthenticationException expired = assertThrows(AuthenticationException.class,
                () -> noIdleAuth.refresh(n.token()));
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, expired.getReason());
        log.info("对照组 credentialId={} 判定依据=now>=expiresAt -> CREDENTIAL_EXPIRED，"
                + "与 SESSION_IDLE_TIMEOUT 机器可读地区分", n.credentialId());
    }

    @Test
    void refreshSuccessSlidesIdleWindow() {
        TokenResponse t = auth.login("alice", "pw");
        // 每次都在空闲窗口内刷新：窗口随之后移，远超初始签发+IDLE 仍可用
        TokenResponse current = t;
        for (int i = 0; i < 5; i++) {
            clock.advance(IDLE - 1);
            current = auth.refresh(current.token());
        }
        log.info("连续顺延 credentialId={} 判定依据=每次刷新成功都重置 lastActiveAt, "
                + "总时长 {}ms 远超单次空闲上限 {}ms", current.credentialId(), 5 * (IDLE - 1), IDLE);
        // 停止活动：到达空闲边界即拒绝
        clock.advance(IDLE);
        TokenResponse stopped = current;
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(stopped.token()));
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT, ex.getReason());
    }

    @Test
    void allowedAccessSlidesIdleWindowButDeniedAccessDoesNot() {
        TokenResponse t = auth.login("alice", "pw");
        // 放行式访问是活动：顺延空闲窗口
        clock.advance(IDLE - 1);
        assertTrue(access.decide(t.token(), "profile:read", "p").isAllowed());
        clock.advance(IDLE - 1); // 距上次放行 9s，距登录已 18s
        assertTrue(access.decide(t.token(), "profile:read", "p").isAllowed(),
                "放行式访问应顺延空闲窗口");
        log.info("访问顺延 credentialId={} 判定依据=ALLOW 判定触发 touch, 18s>IDLE 但会话仍活跃",
                t.credentialId());

        // 权限不足的访问不算活动：不顺延
        clock.advance(IDLE - 1);
        assertEquals(DenyReason.PERMISSION_DENIED,
                access.decide(t.token(), "admin:read", "a").getReason());
        clock.advance(1); // 距上次“放行”恰好 IDLE
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT,
                access.decide(t.token(), "profile:read", "p").getReason());
        log.info("拒绝不顺延 credentialId={} 判定依据=PERMISSION_DENIED 不触发 touch, "
                + "空闲窗口到期 -> SESSION_IDLE_TIMEOUT", t.credentialId());
    }

    @Test
    void terminationReasonsBeatIdleAndIdleBeatsRotation() {
        // 1) 撤销 + 空闲叠加：撤销类优先
        TokenResponse revoked = auth.login("alice", "pw");
        auth.revokeSession(revoked.sessionId(), "logout");
        clock.advance(IDLE + 1);
        assertEquals(DenyReason.SESSION_REVOKED,
                access.decide(revoked.token(), "profile:read", "p").getReason());
        AuthenticationException revokedRefresh = assertThrows(AuthenticationException.class,
                () -> auth.refresh(revoked.token()));
        assertEquals(DenyReason.SESSION_REVOKED, revokedRefresh.getReason());
        log.info("撤销+空闲 credentialId={} 判定依据=终止类优先 -> SESSION_REVOKED（非 IDLE_TIMEOUT）",
                revoked.credentialId());

        // 2) 容量淘汰 + 空闲叠加：淘汰原因稳定为 CAPACITY_EVICTED
        InMemoryUserStore users2 = new InMemoryUserStore();
        PasswordHasher hasher = new PasswordHasher();
        users2.save(new UserAccount("u-9", "mallory", hasher.hash("pw", "s9"), "s9",
                Set.of("USER"), Map.of(), true));
        DefaultAuthService maxOneAuth = new DefaultAuthService(users2,
                new InMemorySessionStore(), new LocalHmacTokenService("test-secret"), hasher,
                new DefaultAuditService(new InMemoryAuditStore(), clock), clock,
                TTL, 1, IDLE);
        TokenResponse evicted = maxOneAuth.login("mallory", "pw");
        maxOneAuth.login("mallory", "pw"); // 触发容量淘汰第一个会话
        clock.advance(IDLE + 1);
        AuthenticationException evictedEx = assertThrows(AuthenticationException.class,
                () -> maxOneAuth.refresh(evicted.token()));
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, evictedEx.getReason());
        log.info("淘汰+空闲 credentialId={} 判定依据=终止类优先 -> SESSION_CAPACITY_EVICTED（非 IDLE_TIMEOUT）",
                evicted.credentialId());

        // 3) 轮换 + 空闲叠加：空闲先于轮换判定（整个会话已空闲死亡）
        TokenResponse first = auth.login("alice", "pw");
        TokenResponse second = auth.refresh(first.token());
        clock.advance(IDLE);
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT,
                access.decide(first.token(), "profile:read", "p").getReason());
        AuthenticationException replay = assertThrows(AuthenticationException.class,
                () -> auth.refresh(first.token()));
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT, replay.getReason());
        log.info("轮换+空闲 credentialId={} 判定依据=空闲判定先于轮换 -> SESSION_IDLE_TIMEOUT（非 ROTATED）",
                first.credentialId());
        // 当前凭证同样空闲超时
        assertEquals(DenyReason.SESSION_IDLE_TIMEOUT,
                access.decide(second.token(), "profile:read", "p").getReason());
    }

    @Test
    void absoluteExpiryIsReportedWhenItPrecedesIdle() {
        // TTL < IDLE 的独立夹具：绝对过期先触发，原因必须是 CREDENTIAL_EXPIRED
        InMemoryUserStore users = new InMemoryUserStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        InMemorySessionStore store = new InMemorySessionStore();
        DefaultAuthService shortTtlAuth = new DefaultAuthService(users, store,
                new LocalHmacTokenService("test-secret"), hasher,
                new DefaultAuditService(new InMemoryAuditStore(), clock), clock,
                5_000L, 5, IDLE);
        TokenResponse t = shortTtlAuth.login("alice", "pw");
        clock.advance(5_000); // 绝对过期，但距 lastActiveAt 仅 5s < IDLE
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> shortTtlAuth.refresh(t.token()));
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, ex.getReason());
        log.info("过期先于空闲 credentialId={} 判定依据=绝对过期判定先于空闲 -> CREDENTIAL_EXPIRED",
                t.credentialId());
    }
}
