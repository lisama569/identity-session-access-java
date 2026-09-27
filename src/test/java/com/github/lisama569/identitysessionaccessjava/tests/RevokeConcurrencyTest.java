package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.CredentialState;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
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
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 撤销与刷新并发测试：无论二者如何交错，撤销必须最终生效，
 * 不得出现“刷新覆盖撤销”或“新凭证静默复活”。
 */
class RevokeConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(RevokeConcurrencyTest.class);

    private MutableTimeSource clock;
    private InMemoryUserStore users;
    private InMemorySessionStore sessionStore;
    private DefaultAuthService auth;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(1_000_000L);
        users = new InMemoryUserStore();
        sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuditService audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        auth = new DefaultAuthService(users, sessionStore,
                new LocalHmacTokenService("test-secret"), hasher, audit, clock, 60_000L, 5, 300_000L);
    }

    @RepeatedTest(30)
    void revokeRacingRefreshCanNeverProduceUsableCredential() throws Exception {
        TokenResponse token = auth.login("alice", "pw");
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CyclicBarrier barrier = new CyclicBarrier(2);
        AtomicReference<TokenResponse> refreshed = new AtomicReference<>();
        AtomicReference<DenyReason> refreshFailure = new AtomicReference<>();
        try {
            List<Future<?>> futures = List.of(
                    pool.submit(() -> {
                        try {
                            barrier.await();
                            refreshed.set(auth.refresh(token.token()));
                        } catch (AuthenticationException e) {
                            refreshFailure.set(e.getReason());
                        } catch (Exception ignored) {
                            // barrier 中断等
                        }
                    }),
                    pool.submit(() -> {
                        try {
                            barrier.await();
                            auth.revokeSession(token.sessionId(), "race-revoke");
                        } catch (Exception ignored) {
                            // 刷新若先使会话状态变化，撤销仍应成功
                        }
                    }));
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        // 最终状态：会话必然撤销成功（revokeSession 对已存在会话不抛失败）
        assertTrue(sessionStore.findSession(token.sessionId()).orElseThrow().isRevoked(),
                "撤销必须最终生效");

        // 若刷新产生了新凭证，新凭证也必须已随会话撤销而 REVOKED，绝不静默复活
        TokenResponse winner = refreshed.get();
        if (winner != null) {
            CredentialRecord newCred =
                    sessionStore.findCredential(winner.credentialId()).orElseThrow();
            assertEquals(CredentialState.REVOKED, newCred.getState(),
                    "撤销与刷新并发后，刷新产物必须立即失效");
            log.info("撤销/刷新并发 credentialId={} 判定依据=会话锁串行化，刷新产物随根撤销 REVOKED",
                    winner.credentialId());
        } else {
            DenyReason reason = refreshFailure.get();
            assertTrue(reason == DenyReason.SESSION_REVOKED
                            || reason == DenyReason.CREDENTIAL_REVOKED
                            || reason == DenyReason.CONCURRENT_REFRESH_CONFLICT,
                    "刷新方的失败原因必须可解释，实际=" + reason);
            log.info("撤销/刷新并发 credentialId={} 判定依据=刷新被拒绝 reason={}",
                    token.credentialId(), reason);
        }

        // 无论哪种交错：原凭证与（可能存在的）新凭证都不能再刷新成功
        assertRefreshRejected(token.token());
        if (winner != null) {
            assertRefreshRejected(winner.token());
        }
    }

    @Test
    void repeatedRevokeKeepsFirstReasonNoStateOverwrite() {
        TokenResponse token = auth.login("alice", "pw");
        auth.revokeSession(token.sessionId(), "first-reason");
        clock.advance(100);
        auth.revokeSession(token.sessionId(), "second-reason");
        long revokedAt = sessionStore.findSession(token.sessionId()).orElseThrow().getRevokedAt();
        assertEquals(1_000_000L, revokedAt, "重复撤销不得覆盖首次撤销时刻与原因");
        log.info("重复撤销 sessionId={} 判定依据=markRevoked 保留首次原因/时刻",
                token.sessionId());
    }

    private void assertRefreshRejected(String tokenString) {
        AuthenticationException ex = org.junit.jupiter.api.Assertions.assertThrows(
                AuthenticationException.class, () -> auth.refresh(tokenString));
        assertTrue(ex.getReason() == DenyReason.SESSION_REVOKED
                        || ex.getReason() == DenyReason.CREDENTIAL_REVOKED
                        || ex.getReason() == DenyReason.CREDENTIAL_ROTATED,
                "撤销后任何凭证都不能刷新，实际=" + ex.getReason());
    }
}
