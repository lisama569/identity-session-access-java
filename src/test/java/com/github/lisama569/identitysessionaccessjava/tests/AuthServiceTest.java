package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 认证服务测试：轮换后旧凭证确定失效、事后重放与过期边界原因可区分、撤销后禁止刷新。
 */
class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);
    private static final long TTL = 10_000L;

    private MutableTimeSource clock;
    private InMemorySessionStore sessionStore;
    private DefaultAuthService auth;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(1_000_000L);
        InMemoryUserStore users = new InMemoryUserStore();
        sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of("dept", "engineering"), true));
        users.save(new UserAccount("u-2", "carol", hasher.hash("pw", "salt2"), "salt2",
                Set.of("USER"), Map.of(), false));
        DefaultAuditService audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        auth = new DefaultAuthService(users, sessionStore,
                new LocalHmacTokenService("test-secret"), hasher, audit, clock, TTL, 5, 300_000L);
    }

    @Test
    void loginFailureReasonsAreDistinguishable() {
        AuthenticationException bad = assertThrows(AuthenticationException.class,
                () -> auth.login("alice", "wrong"));
        assertEquals(DenyReason.BAD_CREDENTIALS, bad.getReason());
        AuthenticationException disabled = assertThrows(AuthenticationException.class,
                () -> auth.login("carol", "pw"));
        assertEquals(DenyReason.USER_DISABLED, disabled.getReason());
        log.info("登录拒绝凭证标识=- 判定依据=BAD_CREDENTIALS / USER_DISABLED 可区分");
    }

    @Test
    void rotationImmediatelyInvalidatesOldCredential() {
        TokenResponse first = auth.login("alice", "pw");
        log.info("登录成功 credentialId={} 判定依据=口令匹配且账户启用, version={}",
                first.credentialId(), first.version());

        TokenResponse second = auth.refresh(first.token());
        assertEquals(2L, second.version());
        assertNotEquals(first.credentialId(), second.credentialId());
        log.info("刷新成功 newCredentialId={} 判定依据=旧凭证为会话当前指针且未过期, 旧 credentialId={} 立即 ROTATED",
                second.credentialId(), first.credentialId());

        // 事后用旧凭证重放：必须以 CREDENTIAL_ROTATED 被拒，而不是“恰好过期”之类含混结果
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(first.token()));
        assertEquals(DenyReason.CREDENTIAL_ROTATED, ex.getReason());
        assertEquals(first.credentialId(), ex.getCredentialId());
        log.info("旧凭证重放 credentialId={} 判定依据=状态为 ROTATED -> CREDENTIAL_ROTATED",
                ex.getCredentialId());

        // 新凭证仍然有效
        TokenResponse third = auth.refresh(second.token());
        assertEquals(3L, third.version());
        log.info("链式刷新成功 credentialId={} 判定依据=当前 ACTIVE 凭证 v3", third.credentialId());
    }

    @Test
    void expiryBoundaryIsExactAndReasonsDifferFromRotation() {
        TokenResponse token = auth.login("alice", "pw");

        // 过期前 1ms：仍然有效
        clock.advance(TTL - 1);
        TokenResponse refreshed = auth.refresh(token.token());
        log.info("过期前 1ms credentialId={} 判定依据=now<expiresAt, 刷新成功 v{}",
                refreshed.credentialId(), refreshed.version());

        // 新凭证拥有完整 TTL 窗口；恰在其过期时刻：边界定义 now >= expiresAt 即过期
        clock.advance(TTL);
        AuthenticationException expired = assertThrows(AuthenticationException.class,
                () -> auth.refresh(refreshed.token()));
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, expired.getReason());
        log.info("过期边界 credentialId={} 判定依据=now==expiresAt -> CREDENTIAL_EXPIRED",
                expired.getCredentialId());

        clock.advance(5_000);
        AuthenticationException stillExpired = assertThrows(AuthenticationException.class,
                () -> auth.refresh(refreshed.token()));
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, stillExpired.getReason());
        log.info("过期后 credentialId={} 判定依据=now>expiresAt -> CREDENTIAL_EXPIRED（过期不会复活）",
                stillExpired.getCredentialId());
    }

    @Test
    void revokedSessionRejectsRefreshImmediately() {
        TokenResponse token = auth.login("alice", "pw");
        auth.revokeSession(token.sessionId(), "unit-test-logout");
        clock.advance(1);

        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(token.token()));
        assertEquals(DenyReason.SESSION_REVOKED, ex.getReason());
        log.info("撤销后刷新 credentialId={} 判定依据=会话撤销位优先于过期/轮换 -> SESSION_REVOKED",
                token.credentialId());
    }

    @Test
    void revokedCredentialRejectsRefresh() {
        TokenResponse token = auth.login("alice", "pw");
        auth.revokeCredential(token.credentialId(), "admin-kill");
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(token.token()));
        assertEquals(DenyReason.CREDENTIAL_REVOKED, ex.getReason());
        log.info("凭证撤销后刷新 credentialId={} 判定依据=凭证状态 REVOKED -> CREDENTIAL_REVOKED",
                token.credentialId());
    }
}
