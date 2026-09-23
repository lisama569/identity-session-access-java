package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.auth.exception.AuthDenyException;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessDecision;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.AuditAction;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.IssuedCredential;
import com.github.lisama569.identitysessionaccessjava.auth.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenStatus;
import com.github.lisama569.identitysessionaccessjava.auth.support.TestFixture;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 撤销传播与“撤销 × 刷新”竞态测试。
 *
 * <p>无论撤销与刷新以何种顺序在会话锁上交错，最终状态必须满足：
 * 会话已撤销且不存在静默复活的 ACTIVE 凭证；两条路径各自留下审计记录。</p>
 */
class RevocationConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(RevocationConcurrencyTest.class);

    private final AccessRequest readPublic =
            new AccessRequest("public/welcome", "read", java.util.Map.of());

    @Test
    void revokeThenAccessIsDeniedImmediatelyWithDistinctReason() {
        TestFixture f = TestFixture.create();
        IssuedCredential c = f.auth().login("bob", "bob-pw");

        AccessDecision ok = f.access().authorize(c.token(), readPublic);
        assertTrue(ok.allowed());

        f.auth().revokeToken(c.token(), "user requested sign-out");
        log.info("[REVOKE] revoked tokenId={}", c.tokenId());

        AccessDecision denied = f.access().authorize(c.token(), readPublic);
        log.info("[REVOKE] access after revoke tokenId={} allowed={} reason={} basis={}",
                c.tokenId(), denied.allowed(), denied.reason(), denied.basis());
        assertFalse(denied.allowed());
        // 撤销凭证即撤销整条凭证链：会话撤销优先呈现，凭证撤销亦可，二者均为可区分的撤销类原因。
        assertTrue(denied.reason() == DenyReason.SESSION_REVOKED
                        || denied.reason() == DenyReason.TOKEN_REVOKED,
                "期望撤销类原因，实际=" + denied.reason());

        // 已撤销凭证不能再刷新出新凭证，杜绝“撤销后静默复活”。
        AuthDenyException refreshAfter = assertThrows(AuthDenyException.class,
                () -> f.auth().refresh(c.token()));
        assertTrue(refreshAfter.getReason() == DenyReason.SESSION_REVOKED
                        || refreshAfter.getReason() == DenyReason.TOKEN_REVOKED,
                "期望撤销类原因，实际=" + refreshAfter.getReason());
    }

    @Test
    void revokeSessionAndRevokeUserSessionsInvalidateCurrentCredential() {
        TestFixture f = TestFixture.create();
        IssuedCredential a = f.auth().login("alice", "alice-pw");
        IssuedCredential a2 = f.auth().login("alice", "alice-pw");

        f.auth().revokeUserSessions("u-alice", "security incident");
        log.info("[REVOKE] all sessions of u-alice revoked, tokenIds={},{}",
                a.tokenId(), a2.tokenId());

        for (IssuedCredential c : List.of(a, a2)) {
            AccessDecision d = f.access().authorize(c.token(), readPublic);
            assertFalse(d.allowed());
            assertTrue(d.reason() == DenyReason.SESSION_REVOKED
                            || d.reason() == DenyReason.TOKEN_REVOKED,
                    "期望撤销类原因，实际=" + d.reason());
        }
        assertTrue(f.sessions().getSession(a.sessionId()).isRevoked());
        assertTrue(f.sessions().getSession(a2.sessionId()).isRevoked());
    }

    @Test
    void concurrentRevokeAndRefreshNeverLeaveAnActiveCredential() throws Exception {
        // 重复多轮以覆盖两种交错：撤销先拿锁 / 刷新先拿锁。
        for (int round = 0; round < 20; round++) {
            final int roundNo = round;
            TestFixture f = TestFixture.create();
            IssuedCredential c = f.auth().login("alice", "alice-pw");

            ReentrantLock sessionLock = f.sessions().lockFor(c.sessionId());
            sessionLock.lock();

            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger refreshOk = new AtomicInteger();
            AtomicInteger refreshDenied = new AtomicInteger();

            var refreshFuture = pool.submit(() -> {
                try {
                    start.await();
                    f.auth().refresh(c.token());
                    refreshOk.incrementAndGet();
                } catch (AuthDenyException ex) {
                    refreshDenied.incrementAndGet();
                    log.info("[REVOKE-RACE] round={} refresh lost reason={}", roundNo, ex.getReason());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            });
            var revokeFuture = pool.submit(() -> {
                try {
                    start.await();
                    f.auth().revokeToken(c.token(), "race-test");
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            });

            start.countDown();
            Thread.sleep(50);
            sessionLock.unlock();
            refreshFuture.get();
            revokeFuture.get();
            pool.shutdown();

            SessionInfo session = f.sessions().getSession(c.sessionId());
            long active = f.sessions().allTokens().stream()
                    .filter(t -> t.getSessionId().equals(c.sessionId()))
                    .filter(t -> t.getStatus() == TokenStatus.ACTIVE)
                    .count();

            log.info("[REVOKE-RACE] round={} refreshOk={} refreshDenied={} sessionRevoked={} activeTokens={}",
                    round, refreshOk.get(), refreshDenied.get(), session.isRevoked(), active);

            assertTrue(session.isRevoked(), "撤销最终必须生效");
            assertEquals(0L, active, "撤销与刷新并发后不得残留有效凭证（禁止静默复活）");
            assertEquals(1, refreshOk.get() + refreshDenied.get());

            // 即便刷新先成功，会话指针上的新凭证也必须已被撤销动作撤销。
            if (refreshOk.get() == 1) {
                TokenInfo current = f.sessions().tokenById(session.getCurrentTokenId());
                assertEquals(TokenStatus.REVOKED, current.getStatus());
            }
        }
    }

    @Test
    void auditTrailContainsLoginRefreshDenyAndRevokeInOrder() {
        TestFixture f = TestFixture.create();
        IssuedCredential c = f.auth().login("carol", "carol-pw");
        IssuedCredential c2 = f.auth().refresh(c.token());
        f.access().authorize(c.token(), readPublic);           // 旧凭证重放访问
        f.auth().revokeToken(c2.token(), "audit-check");

        List<AuditAction> actions = f.auditService().events().stream()
                .map(e -> e.action())
                .toList();
        log.info("[AUDIT-TRAIL] {}", actions);
        assertTrue(actions.contains(AuditAction.LOGIN_SUCCESS));
        assertTrue(actions.contains(AuditAction.REFRESH_SUCCESS));
        assertTrue(actions.contains(AuditAction.ACCESS_DENIED));
        assertTrue(actions.contains(AuditAction.TOKEN_REVOKED));
        // 序列号严格单调递增。
        long previous = 0;
        for (var event : f.audits().events()) {
            assertTrue(event.sequence() > previous);
            previous = event.sequence();
        }
    }
}
