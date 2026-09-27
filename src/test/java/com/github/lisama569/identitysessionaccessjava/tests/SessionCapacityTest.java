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
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 账号级会话容量测试：活跃会话数不超过上限；超出时最久未活跃者先出局；
 * 被淘汰会话的凭证立即失效且原因与未认证/过期/主动撤销可区分；
 * 并发登录与淘汰竞争收敛后仍满足容量不变量。
 */
class SessionCapacityTest {

    private static final Logger log = LoggerFactory.getLogger(SessionCapacityTest.class);
    private static final long TTL = 60_000L;
    // 空闲窗口短于 TTL（启动校验要求），且大于本类测试中推进的最大时间跨度，
    // 因此容量相关用例不会误触空闲判定。
    private static final long IDLE = 30_000L;
    private static final int MAX_SESSIONS = 3;

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
                TTL, MAX_SESSIONS, IDLE);
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock, IDLE);
    }

    @Test
    void capacityEvictsLeastRecentlyActiveFirst() {
        TokenResponse s1 = auth.login("alice", "pw");
        clock.advance(100);
        TokenResponse s2 = auth.login("alice", "pw");
        clock.advance(100);
        TokenResponse s3 = auth.login("alice", "pw");
        assertEquals(3, auth.listActiveSessions("alice").size());

        // s2 有一次活动（刷新），s1 成为最久未活跃者
        clock.advance(100);
        TokenResponse s2b = auth.refresh(s2.token());

        // 第 4 次登录超出上限：s1（最久未活跃）被淘汰，而不是有活动的 s2
        clock.advance(100);
        TokenResponse s4 = auth.login("alice", "pw");

        List<SessionView> views = auth.listActiveSessions("alice");
        assertEquals(MAX_SESSIONS, views.size());
        List<String> activeIds = views.stream().map(SessionView::sessionId).toList();
        assertTrue(activeIds.containsAll(
                List.of(s2.sessionId(), s3.sessionId(), s4.sessionId())));
        assertTrue(activeIds.stream().noneMatch(id -> id.equals(s1.sessionId())));
        log.info("容量淘汰 session={} credential={} 判定依据=lastActiveAt 最久未活跃先出局, "
                        + "存活会话={}", s1.sessionId(), s1.credentialId(), activeIds);

        // 被淘汰会话的凭证：访问与刷新都以 SESSION_CAPACITY_EVICTED 拒绝
        AuthDecision denied = access.decide(s1.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, denied.getReason());
        log.info("被淘汰凭证访问 credential={} 判定依据=会话撤销类别=CAPACITY -> "
                + "SESSION_CAPACITY_EVICTED", s1.credentialId());
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(s1.token()));
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, ex.getReason());
        log.info("被淘汰凭证刷新 credential={} 判定依据=锁内撤销位+CAPACITY 类别 -> "
                + "SESSION_CAPACITY_EVICTED", ex.getCredentialId());

        // 其余会话（含刷新过代次的 s2）照常可用
        assertTrue(access.decide(s2b.token(), "profile:read", "profile").isAllowed());
        assertTrue(access.decide(s3.token(), "profile:read", "profile").isAllowed());
        assertTrue(access.decide(s4.token(), "profile:read", "profile").isAllowed());
    }

    @Test
    void evictionReasonIsDistinctFromOtherDenyReasons() {
        TokenResponse s1 = auth.login("alice", "pw");
        clock.advance(10);
        auth.login("alice", "pw");
        clock.advance(10);
        auth.login("alice", "pw");
        clock.advance(10);
        auth.login("alice", "pw"); // 淘汰 s1（最久未活跃）

        // 容量淘汰
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED,
                access.decide(s1.token(), "profile:read", "profile").getReason());
        // 主动撤销
        TokenResponse s5 = auth.login("alice", "pw");
        auth.revokeSession(s5.sessionId(), "user-logout");
        assertEquals(DenyReason.SESSION_REVOKED,
                access.decide(s5.token(), "profile:read", "profile").getReason());
        // 自然过期：保持活跃（访问顺延空闲窗口）直到凭证绝对有效期
        TokenResponse s6 = auth.login("alice", "pw");
        long elapsed = 0;
        while (elapsed + (IDLE - 1_000) < TTL) {
            clock.advance(IDLE - 1_000);
            elapsed += IDLE - 1_000;
            assertTrue(access.decide(s6.token(), "profile:read", "profile").isAllowed());
        }
        clock.advance(TTL - elapsed);
        assertEquals(DenyReason.CREDENTIAL_EXPIRED,
                access.decide(s6.token(), "profile:read", "profile").getReason());
        // 未认证
        assertEquals(DenyReason.UNAUTHENTICATED,
                access.decide(null, "profile:read", "profile").getReason());
        log.info("拒绝原因可区分 credential={} 判定依据=CAPACITY_EVICTED / SESSION_REVOKED / "
                + "CREDENTIAL_EXPIRED / UNAUTHENTICATED 四者互不相同", s1.credentialId());
    }

    @RepeatedTest(10)
    void concurrentLoginsConvergeToCapacityLimit() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        Set<TokenResponse> issued = ConcurrentHashMap.newKeySet();
        try {
            List<Future<Void>> futures = IntStream.range(0, threads).mapToObj(i ->
                    (java.util.concurrent.Callable<Void>) () -> {
                        barrier.await();
                        issued.add(auth.login("alice", "pw"));
                        return null;
                    }).map(pool::submit).toList();
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        // 收敛后：活跃会话数恰为上限，不多不少
        List<SessionView> active = auth.listActiveSessions("alice");
        assertEquals(MAX_SESSIONS, active.size());
        Set<String> activeSessionIds = ConcurrentHashMap.newKeySet();
        active.forEach(v -> activeSessionIds.add(v.sessionId()));

        int evictedDenied = 0;
        int activeAllowed = 0;
        for (TokenResponse t : issued) {
            AuthDecision d = access.decide(t.token(), "profile:read", "profile");
            if (activeSessionIds.contains(t.sessionId())) {
                // 存活会话：其当前凭证必须可用，且每个会话只有一张有效凭证
                assertTrue(d.isAllowed(), "存活会话的凭证必须可用: " + t.sessionId());
                activeAllowed++;
            } else {
                // 被淘汰会话：凭证绝不复活，原因确定
                assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, d.getReason());
                evictedDenied++;
            }
        }
        assertEquals(MAX_SESSIONS, activeAllowed);
        assertEquals(threads - MAX_SESSIONS, evictedDenied);
        log.info("并发登录收敛 判定依据=账号锁内建会话+淘汰原子完成, 活跃={} 上限={} "
                        + "被淘汰且拒绝={}", activeAllowed, MAX_SESSIONS, evictedDenied);
    }

    @RepeatedTest(10)
    void refreshRacingEvictionNeverLeavesUsableEvictedCredential() throws Exception {
        // 先占满容量
        TokenResponse first = auth.login("alice", "pw");
        auth.login("alice", "pw");
        auth.login("alice", "pw");

        // 一边对最早会话刷新，一边并发登录触发容量淘汰
        int logins = 4;
        ExecutorService pool = Executors.newFixedThreadPool(logins + 1);
        CyclicBarrier barrier = new CyclicBarrier(logins + 1);
        Set<TokenResponse> newLogins = ConcurrentHashMap.newKeySet();
        try {
            Future<?> refresher = pool.submit(() -> {
                try {
                    barrier.await();
                    try {
                        auth.refresh(first.token());
                    } catch (AuthenticationException expected) {
                        // 被淘汰则拒绝，属于合法结果
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            List<Future<Void>> futures = IntStream.range(0, logins).mapToObj(i ->
                    (java.util.concurrent.Callable<Void>) () -> {
                        barrier.await();
                        newLogins.add(auth.login("alice", "pw"));
                        return null;
                    }).map(pool::submit).toList();
            refresher.get();
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        // 收敛后不变量：活跃会话数 <= 上限
        List<SessionView> active = auth.listActiveSessions("alice");
        assertTrue(active.size() <= MAX_SESSIONS,
                "活跃会话数不得超过上限: " + active.size());
        // 最早会话无论刷新输赢，最终都不能持有可用凭证（被淘汰即失效，不复活）
        AuthDecision d = access.decide(first.token(), "profile:read", "profile");
        assertTrue(!d.isAllowed(), "被淘汰会话的旧凭证不得可用");
        log.info("刷新与淘汰竞争收敛 credential={} 判定依据=淘汰在账号锁内完成, "
                + "旧凭证拒绝原因={} 活跃会话数={}/{}", first.credentialId(), d.getReason(),
                active.size(), MAX_SESSIONS);
    }
}
