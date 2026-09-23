package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
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
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发刷新测试：多个线程在屏障处同时用同一张旧凭证刷新，
 * 必须恰有一个赢家，其余全部得到 CONCURRENT_REFRESH_CONFLICT，
 * 且会话当前只存在一张 ACTIVE 凭证。
 */
class ConcurrentRefreshTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRefreshTest.class);
    private static final int THREADS = 16;

    private MutableTimeSource clock;
    private DefaultAuthService auth;
    private InMemorySessionStore sessionStore;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(1_000_000L);
        InMemoryUserStore users = new InMemoryUserStore();
        sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new com.github.lisama569.identitysessionaccessjava.model.UserAccount(
                "u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuditService audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        auth = new DefaultAuthService(users, sessionStore,
                new LocalHmacTokenService("test-secret"), hasher, audit, clock, 60_000L);
    }

    @RepeatedTest(20)
    void concurrentRefreshProducesExactlyOneWinner() throws Exception {
        TokenResponse first = auth.login("alice", "pw");
        String oldCredentialId = first.credentialId();

        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CyclicBarrier barrier = new CyclicBarrier(THREADS);
        Set<String> winners = ConcurrentHashMap.newKeySet();
        Map<Integer, DenyReason> loserReasons = new ConcurrentHashMap<>();
        try {
            List<Future<?>> futures = IntStream.range(0, THREADS).mapToObj(i ->
                    (java.util.concurrent.Callable<Void>) () -> {
                        // 所有线程在屏障之前完成批次登记，保证赢家在锁内快照时，
                        // 其余竞争者全部已在“在途批次”中——并发分类与调度无关。
                        Object handle = auth.joinRefreshBatch(first.token());
                        try {
                            barrier.await();
                            try {
                                TokenResponse r = auth.refresh(first.token());
                                winners.add(r.credentialId());
                            } catch (AuthenticationException e) {
                                loserReasons.put(i, e.getReason());
                            }
                        } finally {
                            auth.leaveRefreshBatch(handle);
                        }
                        return null;
                    }).map(pool::submit).collect(Collectors.toList());
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        // 1) 恰有一个赢家
        assertEquals(1, winners.size(), "并发刷新必须恰有一个赢家，实际: " + winners);
        String winnerId = winners.iterator().next();
        // 2) 其余全部以“并发刷新冲突”失败（不是过期、不是普通轮换）
        assertEquals(THREADS - 1, loserReasons.size());
        assertTrue(loserReasons.values().stream()
                        .allMatch(r -> r == DenyReason.CONCURRENT_REFRESH_CONFLICT),
                "所有输家都应是 CONCURRENT_REFRESH_CONFLICT，实际: " + loserReasons);
        // 3) 会话当前指针指向赢家，旧凭证已 ROTATED 且记录后继
        var session = sessionStore.findSession(first.sessionId()).orElseThrow();
        assertEquals(winnerId, session.getCurrentCredentialId());
        assertEquals(2L, session.getCurrentVersion());
        var oldCredential = sessionStore.findCredential(oldCredentialId).orElseThrow();
        assertEquals(com.github.lisama569.identitysessionaccessjava.model.CredentialState.ROTATED,
                oldCredential.getState());
        assertEquals(winnerId, oldCredential.getReplacedByCredentialId());
        // 4) 会话名下恰有两张凭证，且只有赢家是 ACTIVE
        long activeCount = sessionStore.credentialsOfSession(first.sessionId()).stream()
                .filter(c -> c.getState()
                        == com.github.lisama569.identitysessionaccessjava.model.CredentialState.ACTIVE)
                .count();
        assertEquals(1L, activeCount, "同一会话并发刷新后不得同时存在两个有效凭证");
        log.info("并发刷新 credentialId={} 判定依据=会话锁+当前指针CAS: 1赢家/{}输家(CONCURRENT_REFRESH_CONFLICT), ACTIVE=1",
                winnerId, THREADS - 1);
    }

    @Test
    void loserTokenIsNotAcceptedLaterAndReplayIsRotated() throws Exception {
        TokenResponse first = auth.login("alice", "pw");
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CyclicBarrier barrier = new CyclicBarrier(2);
        try {
            List<Future<String>> futures = IntStream.range(0, 2).mapToObj(i ->
                    pool.submit(() -> {
                        Object handle = auth.joinRefreshBatch(first.token());
                        try {
                            barrier.await();
                            try {
                                return "WIN:" + auth.refresh(first.token()).credentialId();
                            } catch (AuthenticationException e) {
                                return "LOSE:" + e.getReason();
                            }
                        } finally {
                            auth.leaveRefreshBatch(handle);
                        }
                    })).toList();
            List<String> results = new java.util.ArrayList<>();
            for (Future<String> f : futures) {
                results.add(f.get());
            }
            // 双方均已在屏障前入批：恰一个赢家，输家原因确定为并发冲突
            long wins = results.stream().filter(r -> r.startsWith("WIN:")).count();
            long concurrentLoses = results.stream()
                    .filter(r -> r.equals("LOSE:" + DenyReason.CONCURRENT_REFRESH_CONFLICT.name()))
                    .count();
            assertEquals(1, wins, results.toString());
            assertEquals(1, concurrentLoses, results.toString());
        } finally {
            pool.shutdownNow();
        }

        // 无论并发路径给出哪种原因，旧凭证此后稳定不可用，且归因为事后重放
        AuthenticationException replay = org.junit.jupiter.api.Assertions.assertThrows(
                AuthenticationException.class, () -> auth.refresh(first.token()));
        assertEquals(DenyReason.CREDENTIAL_ROTATED, replay.getReason());
        log.info("旧凭证事后重放 credentialId={} 判定依据=锁内状态 ROTATED 稳定可复现 -> CREDENTIAL_ROTATED",
                first.credentialId());
    }
}
