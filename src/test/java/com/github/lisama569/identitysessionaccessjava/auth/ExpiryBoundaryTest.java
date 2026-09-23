package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.auth.exception.AuthDenyException;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessDecision;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.IssuedCredential;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenStatus;
import com.github.lisama569.identitysessionaccessjava.auth.support.TestFixture;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 过期边界测试（TTL=30s，使用可控时钟）。
 *
 * <p>边界约定：{@code now <= expiresAt} 前有效；到达 {@code expiresAt} 时刻
 * （{@code !expiresAt.isAfter(now)}）立即判为过期。过期结论与“已轮换”“已撤销”
 * 完全可区分，且刷新与访问两个入口结论一致。</p>
 */
class ExpiryBoundaryTest {

    private static final Logger log = LoggerFactory.getLogger(ExpiryBoundaryTest.class);

    private final AccessRequest readPublic =
            new AccessRequest("public/welcome", "read", java.util.Map.of());

    @Test
    void credentialValidBeforeExpiryAndExpiresExactlyAtTtl() {
        TestFixture f = TestFixture.create();
        IssuedCredential c = f.auth().login("carol", "carol-pw");
        log.info("[EXPIRY] issued tokenId={} expiresAt={}", c.tokenId(), c.expiresAt());

        // 距过期 1 秒：仍有效。
        f.clock().advance(Duration.ofSeconds(29));
        AccessDecision before = f.access().authorize(c.token(), readPublic);
        log.info("[EXPIRY] t=29s tokenId={} allowed={}", c.tokenId(), before.allowed());
        assertTrue(before.allowed());
        assertEquals(TokenStatus.ACTIVE, f.sessions().tokenById(c.tokenId()).getStatus());

        // 恰达过期时刻（第 30 秒）：立即过期。
        f.clock().advance(Duration.ofSeconds(1));
        AccessDecision at = f.access().authorize(c.token(), readPublic);
        log.info("[EXPIRY] t=30s tokenId={} allowed={} reason={} basis={}",
                c.tokenId(), at.allowed(), at.reason(), at.basis());
        assertFalse(at.allowed());
        assertEquals(DenyReason.TOKEN_EXPIRED, at.reason());
        // 惰性落状态：过期时刻此刻被持久化为 EXPIRED。
        assertEquals(TokenStatus.EXPIRED, f.sessions().tokenById(c.tokenId()).getStatus());

        // 刷新入口在同一边界上给出一致、可区分的结论。
        AuthDenyException refreshExpired = assertThrows(AuthDenyException.class,
                () -> f.auth().refresh(c.token()));
        assertEquals(DenyReason.TOKEN_EXPIRED, refreshExpired.getReason());
    }

    @Test
    void refreshAtLastSecondBeforeExpiryIssuesFreshCredential() {
        TestFixture f = TestFixture.create();
        IssuedCredential c = f.auth().login("carol", "carol-pw");

        f.clock().advance(Duration.ofSeconds(29));
        IssuedCredential rotated = f.auth().refresh(c.token());
        log.info("[EXPIRY] refreshed near-expiry oldTokenId={} newTokenId={} newExpiresAt={}",
                c.tokenId(), rotated.tokenId(), rotated.expiresAt());

        // 新凭证拥有完整 TTL：再过 30 秒才过期。
        f.clock().advance(Duration.ofSeconds(29));
        assertTrue(f.access().authorize(rotated.token(), readPublic).allowed());
        f.clock().advance(Duration.ofSeconds(1));
        AccessDecision expired = f.access().authorize(rotated.token(), readPublic);
        assertEquals(DenyReason.TOKEN_EXPIRED, expired.reason());

        // 旧凭证始终是 ROTATED 而非 EXPIRED：轮换优先，两类历史可区分。
        assertEquals(TokenStatus.ROTATED, f.sessions().tokenById(c.tokenId()).getStatus());
    }

    @Test
    void missingCredentialIsUnauthenticatedNotExpired() {
        TestFixture f = TestFixture.create();
        AccessDecision none = f.access().authorize(null, readPublic);
        assertEquals(DenyReason.UNAUTHENTICATED, none.reason());
        AccessDecision garbage = f.access().authorize("Bearer deadbeef", readPublic);
        assertEquals(DenyReason.UNAUTHENTICATED, garbage.reason());
        log.info("[EXPIRY] no/unknown credential reasons: {}, {}", none.reason(), garbage.reason());
    }
}
