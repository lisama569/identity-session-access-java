package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.DefaultAccessControlService;
import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
import com.github.lisama569.identitysessionaccessjava.access.RoleBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.audit.AuditService;
import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.AuditEventType;
import com.github.lisama569.identitysessionaccessjava.model.CredentialState;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;
import com.github.lisama569.identitysessionaccessjava.store.InMemoryAuditStore;
import com.github.lisama569.identitysessionaccessjava.store.InMemorySessionStore;
import com.github.lisama569.identitysessionaccessjava.store.InMemoryUserStore;
import com.github.lisama569.identitysessionaccessjava.tests.support.MutableTimeSource;
import com.github.lisama569.identitysessionaccessjava.token.LocalHmacTokenService;
import com.github.lisama569.identitysessionaccessjava.web.dto.SessionView;
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
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 账号级会话容量控制测试：最久未活跃者先出局、容量淘汰原因可区分、
 * 并发登录/刷新与淘汰同时发生时收敛后不超上限、被淘汰凭证绝不复活。
 */
class SessionCapacityTest {

    private static final Logger log = LoggerFactory.getLogger(SessionCapacityTest.class);
    private static final long TTL = 60_000L;
    private static final int MAX = 3;

    private MutableTimeSource clock;
    private InMemorySessionStore sessionStore;
    private DefaultAuthService auth;
    private DefaultAccessControlService access;
    private AuditService audit;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(1_000_000L);
        InMemoryUserStore users = new InMemoryUserStore();
        sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokens = new LocalHmacTokenService("test-secret");
        auth = new DefaultAuthService(users, sessionStore, tokens, hasher, audit, clock,
                TTL, MAX, 300_000L);
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock, 300_000L);
    }

    @Test
    void leastRecentlyActiveSessionIsEvictedFirst() {
        TokenResponse s1 = auth.login("alice", "pw");
        clock.advance(1_000);
        TokenResponse s2 = auth.login("alice", "pw");
        clock.advance(1_000);
        TokenResponse s3 = auth.login("alice", "pw");
        clock.advance(1_000);
        // s1 刷新一次 -> 最近活跃时间最新；此时最久未活跃的是 s2
        TokenResponse s1v2 = auth.refresh(s1.token());
        clock.advance(1_000);

        TokenResponse s4 = auth.login("alice", "pw");
        log.info("容量淘汰 credentialId={} 判定依据=活跃会话数超上限 {}, 最久未活跃 s2(credentialId={}) 出局",
                s4.credentialId(), MAX, s2.credentialId());

        // s2 被淘汰：刷新与访问都是 SESSION_CAPACITY_EVICTED
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(s2.token()));
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, ex.getReason());
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED,
                access.decide(s2.token(), "profile:read", "p").getReason());
        log.info("被淘汰会话 credentialId={} 判定依据=终止原因类别 CAPACITY_EVICTED -> SESSION_CAPACITY_EVICTED",
                s2.credentialId());

        // 其余会话（含刚刷新过的 s1、未动的 s3、新登录的 s4）照常可用
        assertTrue(access.decide(s1v2.token(), "profile:read", "p").isAllowed());
        assertTrue(access.decide(s3.token(), "profile:read", "p").isAllowed());
        assertTrue(access.decide(s4.token(), "profile:read", "p").isAllowed());
        assertEquals(3, auth.listActiveSessions("alice").size());

        // 容量淘汰写审计，原因机器可读
        assertTrue(audit.bySession(s2.sessionId()).stream()
                .anyMatch(e -> e.type() == AuditEventType.SESSION_CAPACITY_EVICTED
                        && e.reason() == DenyReason.SESSION_CAPACITY_EVICTED));
    }

    @Test
    void capacityEvictionReasonIsDistinctFromRevokeExpiryAndUnauthenticated() {
        TokenResponse s1 = auth.login("alice", "pw");
        clock.advance(1);
        TokenResponse s2 = auth.login("alice", "pw");
        clock.advance(1);
        TokenResponse s3 = auth.login("alice", "pw");
        clock.advance(1);
        TokenResponse s4 = auth.login("alice", "pw"); // 淘汰最久未活跃的 s1
        clock.advance(1);
        TokenResponse manual = auth.login("alice", "pw"); // 淘汰 s2
        auth.revokeSession(s3.sessionId(), "manual-logout"); // 主动撤销 s3

        // 四种原因互不相同
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED,
                access.decide(s1.token(), "profile:read", "p").getReason());
        assertEquals(DenyReason.SESSION_REVOKED,
                access.decide(s3.token(), "profile:read", "p").getReason());
        assertEquals(DenyReason.UNAUTHENTICATED,
                access.decide(null, "profile:read", "p").getReason());
        clock.advance(TTL + 1);
        // s4 与 manual 已自然过期（且未被淘汰/撤销）：绝对过期原因
        assertEquals(DenyReason.CREDENTIAL_EXPIRED,
                access.decide(s4.token(), "profile:read", "p").getReason());
        // 被淘汰原因在过期之后依然稳定为容量淘汰（终止类优先于过期）
        assertEquals(DenyReason.SESSION_CAPACITY_EVICTED,
                access.decide(s1.token(), "profile:read", "p").getReason());
        log.info("原因可区分 credentialId={} CAPACITY_EVICTED / credentialId={} REVOKED / "
                        + "credentialId={} EXPIRED / 无凭证 UNAUTHENTICATED",
                s1.credentialId(), s3.credentialId(), s4.credentialId());
    }

    @RepeatedTest(20)
    void concurrentLoginsNeverExceedCapacity() throws Exception {
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        Set<TokenResponse> issued = ConcurrentHashMap.newKeySet();
        try {
            List<Future<?>> futures = IntStream.range(0, threads).mapToObj(i ->
                    (java.util.concurrent.Callable<Void>) () -> {
                        barrier.await();
                        issued.add(auth.login("alice", "pw"));
                        return null;
                    }).map(pool::submit).collect(Collectors.toList());
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(threads, issued.size(), "12 个并发登录都应成功签发");

        // 收敛后：活跃会话数恰为上限，不超
        List<SessionView> active = auth.listActiveSessions("alice");
        assertEquals(MAX, active.size(), "并发登录收敛后活跃会话数必须等于上限，实际: " + active);
        // 活跃会话的凭证互不相同（不共用同一张有效凭证）
        assertEquals(MAX, active.stream().map(SessionView::currentCredentialId).distinct().count());

        // 每个存活会话名下恰有一张 ACTIVE 凭证；被淘汰会话的凭证全部不可用
        long activeCredentials = 0;
        for (var session : sessionStore.findSessionsByUser("u-1")) {
            for (var c : sessionStore.credentialsOfSession(session.getId())) {
                if (c.getState() == CredentialState.ACTIVE) {
                    activeCredentials++;
                    assertTrue(active.stream()
                                    .anyMatch(v -> v.currentCredentialId().equals(c.getId())),
                            "ACTIVE 凭证必须属于某个活跃会话，不允许被淘汰会话残留有效凭证: " + c.getId());
                }
            }
        }
        assertEquals(MAX, activeCredentials, "全系统 ACTIVE 凭证数必须等于活跃会话数");

        // 被淘汰会话的旧凭证再使用：一律 SESSION_CAPACITY_EVICTED，绝不复活
        Set<String> activeSessionIds = active.stream().map(SessionView::sessionId)
                .collect(Collectors.toSet());
        int evictedChecked = 0;
        for (TokenResponse t : issued) {
            if (!activeSessionIds.contains(t.sessionId())) {
                AuthenticationException ex = assertThrows(AuthenticationException.class,
                        () -> auth.refresh(t.token()));
                assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, ex.getReason());
                evictedChecked++;
            }
        }
        assertEquals(threads - MAX, evictedChecked);
        log.info("并发容量收敛 判定依据=账号级锁串行化建会话+淘汰: 活跃={} 淘汰={} 全部 SESSION_CAPACITY_EVICTED",
                MAX, evictedChecked);
    }

    @RepeatedTest(20)
    void refreshRacingEvictionNeverLeavesUsableCredential() throws Exception {
        // 上限 1 的独立夹具：登录 s1 后，并发执行「刷新 s1」与「登录 s2（触发淘汰 s1）」
        InMemoryUserStore users = new InMemoryUserStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuthService maxOneAuth = new DefaultAuthService(users, sessionStore,
                new LocalHmacTokenService("test-secret"), hasher,
                new DefaultAuditService(new InMemoryAuditStore(), clock), clock,
                TTL, 1, 300_000L);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            TokenResponse s1 = maxOneAuth.login("alice", "pw");
            CyclicBarrier barrier = new CyclicBarrier(2);
            java.util.concurrent.atomic.AtomicReference<TokenResponse> refreshed =
                    new java.util.concurrent.atomic.AtomicReference<>();
            java.util.concurrent.atomic.AtomicReference<DenyReason> refreshFailure =
                    new java.util.concurrent.atomic.AtomicReference<>();
            List<Future<?>> futures = List.of(
                    pool.submit(() -> {
                        try {
                            barrier.await();
                            refreshed.set(maxOneAuth.refresh(s1.token()));
                        } catch (AuthenticationException e) {
                            refreshFailure.set(e.getReason());
                        } catch (Exception ignored) {
                            // barrier 中断等
                        }
                    }),
                    pool.submit(() -> {
                        try {
                            barrier.await();
                            maxOneAuth.login("alice", "pw"); // 触发容量淘汰 s1
                        } catch (Exception ignored) {
                            // 登录不应失败
                        }
                    }));
            for (Future<?> f : futures) {
                f.get();
            }

            // 收敛后活跃会话数不超过上限 1
            assertEquals(1, maxOneAuth.listActiveSessions("alice").size());

            // 无论交错如何：s1 的旧凭证与（可能签发过的）新凭证都不能再使用
            AuthenticationException oldEx = assertThrows(AuthenticationException.class,
                    () -> maxOneAuth.refresh(s1.token()));
            assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, oldEx.getReason());
            TokenResponse winner = refreshed.get();
            if (winner != null) {
                // 刷新先提交、淘汰后提交：新凭证必须已随会话淘汰而 REVOKED
                assertEquals(CredentialState.REVOKED,
                        sessionStore.findCredential(winner.credentialId()).orElseThrow().getState(),
                        "被淘汰会话的刷新产物必须连带失效，不得静默复活");
                AuthenticationException ex = assertThrows(AuthenticationException.class,
                        () -> maxOneAuth.refresh(winner.token()));
                assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, ex.getReason());
                log.info("刷新/淘汰竞争 credentialId={} 判定依据=会话锁串行化，刷新产物随容量淘汰 REVOKED",
                        winner.credentialId());
            } else {
                assertEquals(DenyReason.SESSION_CAPACITY_EVICTED, refreshFailure.get(),
                        "淘汰先提交时刷新必须以 SESSION_CAPACITY_EVICTED 失败，实际=" + refreshFailure.get());
                log.info("刷新/淘汰竞争 credentialId={} 判定依据=淘汰先提交，刷新 SESSION_CAPACITY_EVICTED",
                        s1.credentialId());
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
