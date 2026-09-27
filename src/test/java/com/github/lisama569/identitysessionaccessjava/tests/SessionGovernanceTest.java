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
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 多设备会话治理测试：按账号列出活跃会话（签发时间 / 最近活跃时间 / 凭证代次），
 * 定向结束其中一个会话后其余会话不受影响，已结束会话不能被重新激活。
 */
class SessionGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceTest.class);
    private static final long TTL = 60_000L;
    private static final long IDLE = 300_000L;
    private static final int MAX_SESSIONS = 5;

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
    void listActiveSessionsShowsIssuedLastActiveAndVersion() {
        TokenResponse s1 = auth.login("alice", "pw");
        clock.advance(1_000);
        TokenResponse s2 = auth.login("alice", "pw");
        clock.advance(1_000);
        TokenResponse s3 = auth.login("alice", "pw");

        List<SessionView> views = auth.listActiveSessions("alice");
        assertEquals(3, views.size());
        for (SessionView v : views) {
            log.info("活跃会话 session={} credential={} 判定依据=未撤销且未过期, issuedAt={} "
                            + "lastActiveAt={} version={}",
                    v.sessionId(), v.currentCredentialId(), v.issuedAt(), v.lastActiveAt(),
                    v.currentVersion());
            assertTrue(v.issuedAt() > 0);
            assertTrue(v.lastActiveAt() >= v.issuedAt());
            assertEquals(1L, v.currentVersion());
        }

        // 第二个会话刷新一次：代次变为 2，最近活跃时间顺延
        clock.advance(500);
        TokenResponse s2b = auth.refresh(s2.token());
        assertEquals(2L, s2b.version());
        SessionView refreshed = auth.listActiveSessions("alice").stream()
                .filter(v -> v.sessionId().equals(s2.sessionId())).findFirst().orElseThrow();
        assertEquals(2L, refreshed.currentVersion());
        assertEquals(s2b.credentialId(), refreshed.currentCredentialId());
        assertTrue(refreshed.lastActiveAt() > refreshed.issuedAt());
        log.info("刷新后视图 session={} credential={} 判定依据=刷新成功顺延活跃时间, version={} "
                        + "lastActiveAt={}",
                refreshed.sessionId(), refreshed.currentCredentialId(),
                refreshed.currentVersion(), refreshed.lastActiveAt());

        // 三个会话互不影响：s1、s3 仍可正常访问
        assertTrue(access.decide(s1.token(), "profile:read", "profile").isAllowed());
        assertTrue(access.decide(s3.token(), "profile:read", "profile").isAllowed());
    }

    @Test
    void targetedTerminateOnlyAffectsThatSession() {
        TokenResponse s1 = auth.login("alice", "pw");
        TokenResponse s2 = auth.login("alice", "pw");
        TokenResponse s3 = auth.login("alice", "pw");

        // 定向结束 s2（模拟“踢掉其中一台设备”）
        auth.revokeSession(s2.sessionId(), "admin-terminate-one-device");
        log.info("定向结束 session={} 判定依据=管理端按会话粒度结束", s2.sessionId());

        // 被结束的会话：访问与刷新都立即拒绝，原因为 SESSION_REVOKED
        AuthDecision denied = access.decide(s2.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_REVOKED, denied.getReason());
        log.info("被结束会话访问 credential={} 判定依据=会话撤销位=true -> SESSION_REVOKED",
                s2.credentialId());
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(s2.token()));
        assertEquals(DenyReason.SESSION_REVOKED, ex.getReason());
        log.info("被结束会话刷新 credential={} 判定依据=锁内撤销位 -> SESSION_REVOKED",
                ex.getCredentialId());

        // 同账号其余会话照常可用
        assertTrue(access.decide(s1.token(), "profile:read", "profile").isAllowed());
        TokenResponse s3b = auth.refresh(s3.token());
        assertEquals(2L, s3b.version());
        log.info("其余会话不受影响 credential={} 判定依据=会话未撤销, 刷新成功 v{}",
                s3b.credentialId(), s3b.version());

        // 治理视图只剩 2 个活跃会话，被结束者不再出现
        List<SessionView> views = auth.listActiveSessions("alice");
        assertEquals(2, views.size());
        assertTrue(views.stream().noneMatch(v -> v.sessionId().equals(s2.sessionId())));
    }

    @Test
    void terminatedSessionCannotBeReactivated() {
        TokenResponse s1 = auth.login("alice", "pw");
        auth.revokeSession(s1.sessionId(), "user-logout");

        // 已结束会话不能通过刷新“复活”
        AuthenticationException refreshEx = assertThrows(AuthenticationException.class,
                () -> auth.refresh(s1.token()));
        assertEquals(DenyReason.SESSION_REVOKED, refreshEx.getReason());
        // 重复结束幂等：保留首次原因，不互相覆盖
        auth.revokeSession(s1.sessionId(), "second-revoke-attempt");
        AuthenticationException stillDenied = assertThrows(AuthenticationException.class,
                () -> auth.refresh(s1.token()));
        assertEquals(DenyReason.SESSION_REVOKED, stillDenied.getReason());
        // 时间推进也不会复活
        clock.advance(TTL * 2);
        AuthDecision decision = access.decide(s1.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_REVOKED, decision.getReason());
        log.info("已结束会话 credential={} 判定依据=撤销为终态, 刷新/等待/重复撤销均不能复活",
                s1.credentialId());
        assertTrue(auth.listActiveSessions("alice").isEmpty());
    }
}
