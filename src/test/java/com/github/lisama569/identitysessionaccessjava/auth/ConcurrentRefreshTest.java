package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.auth.exception.AuthDenyException;
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
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发刷新语义测试。
 *
 * <p>使用会话锁本身构造确定性竞态：主线程先持有会话锁，让所有刷新线程
 * 同时在锁上排队，再统一释放。这样全部线程都观察到旧凭证“入锁前 ACTIVE”，
 * 从而验证：恰一个成功，其余被区分为 {@code CONCURRENTLY_ROTATED}（而非事后重放）。</p>
 */
class ConcurrentRefreshTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRefreshTest.class);

    @Test
    void concurrentRefreshesProduceExactlyOneValidCredential() throws Exception {
        TestFixture f = TestFixture.create();
        IssuedCredential current = f.auth().login("alice", "alice-pw");
        int threads = 16;

        // 主线程先占用会话锁，刷新线程随后全部阻塞在同一把锁上。
        ReentrantLock sessionLock = f.sessions().lockFor(current.sessionId());
        sessionLock.lock();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger concurrentlyRotated = new AtomicInteger();
        AtomicInteger otherFailures = new AtomicInteger();
        List<Future<?>> futures = new java.util.ArrayList<>();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    IssuedCredential won = f.auth().refresh(current.token());
                    success.incrementAndGet();
                    log.info("[CONCURRENT] worker={} won refresh, oldTokenId={} newTokenId={} serial={}",
                            idx, current.tokenId(), won.tokenId(), won.serial());
                } catch (AuthDenyException ex) {
                    if (ex.getReason() == DenyReason.CONCURRENTLY_ROTATED) {
                        concurrentlyRotated.incrementAndGet();
                    } else {
                        otherFailures.incrementAndGet();
                    }
                    log.info("[CONCURRENT] worker={} lost, tokenId={} reason={}",
                            idx, ex.getTokenId(), ex.getReason());
                }
                return null;
            }));
        }

        start.countDown();
        // 等待所有工作线程都进入排队状态后再释放会话锁。
        Thread.sleep(300);
        sessionLock.unlock();

        for (Future<?> future : futures) {
            future.get();
        }
        pool.shutdown();

        log.info("[CONCURRENT] result success={} concurrentlyRotated={} other={}",
                success.get(), concurrentlyRotated.get(), otherFailures.get());

        assertEquals(1, success.get(), "同一会话并发刷新必须恰有一个成功");
        assertEquals(threads - 1, concurrentlyRotated.get(),
                "失败者必须被区分为并发轮换失效");
        assertEquals(0, otherFailures.get());

        // 不变量：会话唯一当前凭证存在且 ACTIVE，旧凭证 ROTATED 并指向后继。
        SessionInfo session = f.sessions().getSession(current.sessionId());
        TokenInfo winner = f.sessions().tokenById(session.getCurrentTokenId());
        assertEquals(2L, session.getCurrentSerial());
        assertEquals(TokenStatus.ACTIVE, winner.getStatus());
        TokenInfo old = f.sessions().tokenById(current.tokenId());
        assertEquals(TokenStatus.ROTATED, old.getStatus());
        assertEquals(winner.getTokenId(), old.getSupersededBy());

        // 全库范围内该会话只有一个 ACTIVE 凭证。
        long activeCount = f.sessions().allTokens().stream()
                .filter(t -> t.getSessionId().equals(current.sessionId()))
                .filter(t -> t.getStatus() == TokenStatus.ACTIVE)
                .count();
        assertEquals(1L, activeCount, "同一会话任意时刻至多一个有效凭证");
    }
}
