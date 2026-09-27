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
import com.github.lisama569.identitysessionaccessjava.web.dto.SessionView;
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
 * 多设备会话治理测试：同账号多会话互不影响、按账号列出活跃会话、
 * 定向结束某一个会话后其余会话照常可用、已结束会话不能重新激活。
 */
class SessionGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceTest.class);
    private static final long TTL = 60_000L;

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
                TTL, 5, 300_000L);
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock, 300_000L);
    }

    @Test
    void multipleSessionsOfSameAccountAreListedAndIndependent() {
        TokenResponse phone = auth.login("alice", "pw");
        clock.advance(1_000);
        TokenResponse laptop = auth.login("alice", "pw");
        clock.advance(1_000);
        TokenResponse tablet = auth.login("alice", "pw");

        List<SessionView> sessions = auth.listActiveSessions("alice");
        assertEquals(3, sessions.size(), "同账号三台设备应各有独立会话");
        // 每个会话都能看出发行时间、最近活跃时间与当前凭证代次
        for (SessionView v : sessions) {
            assertTrue(v.issuedAt() > 0 && v.lastActiveAt() >= v.issuedAt());
            assertEquals(1L, v.currentVersion());
            log.info("活跃会话 sessionId={} credentialId={} issuedAt={} lastActiveAt={} version={}",
                    v.sessionId(), v.currentCredentialId(), v.issuedAt(), v.lastActiveAt(),
                    v.currentVersion());
        }
        assertEquals(Set.of(phone.sessionId(), laptop.sessionId(), tablet.sessionId()),
                Set.copyOf(sessions.stream().map(SessionView::sessionId).toList()));

        // 只刷新其中一台设备：其余会话的代次与凭证不受影响
        TokenResponse phoneV2 = auth.refresh(phone.token());
        assertEquals(2L, phoneV2.version());
        List<SessionView> after = auth.listActiveSessions("alice");
        SessionView phoneView = after.stream()
                .filter(v -> v.sessionId().equals(phone.sessionId())).findFirst().orElseThrow();
        assertEquals(2L, phoneView.currentVersion());
        assertEquals(phoneV2.credentialId(), phoneView.currentCredentialId());
        SessionView laptopView = after.stream()
                .filter(v -> v.sessionId().equals(laptop.sessionId())).findFirst().orElseThrow();
        assertEquals(1L, laptopView.currentVersion());
        assertEquals(laptop.credentialId(), laptopView.currentCredentialId());
        log.info("定向刷新 credentialId={} 判定依据=会话级锁内轮换只影响本会话, 其余会话 version 不变",
                phoneV2.credentialId());

        // 三台设备的当前凭证都能正常访问
        assertTrue(access.decide(phoneV2.token(), "profile:read", "p").isAllowed());
        assertTrue(access.decide(laptop.token(), "profile:read", "p").isAllowed());
        assertTrue(access.decide(tablet.token(), "profile:read", "p").isAllowed());
    }

    @Test
    void terminatingOneSessionLeavesOthersUsableAndTerminatedStaysDead() {
        TokenResponse phone = auth.login("alice", "pw");
        TokenResponse laptop = auth.login("alice", "pw");
        TokenResponse tablet = auth.login("alice", "pw");

        // 定向结束 laptop 会话（踢掉一个设备）
        auth.revokeSession(laptop.sessionId(), "kick-one-device");
        log.info("定向结束 sessionId={} credentialId={} 判定依据=会话级根撤销只作用于目标会话",
                laptop.sessionId(), laptop.credentialId());

        // 列表立即收缩为 2 个活跃会话
        List<SessionView> sessions = auth.listActiveSessions("alice");
        assertEquals(2, sessions.size());
        assertTrue(sessions.stream().noneMatch(v -> v.sessionId().equals(laptop.sessionId())));

        // 被结束会话的凭证立即失效：访问与刷新都是 SESSION_REVOKED
        assertEquals(DenyReason.SESSION_REVOKED,
                access.decide(laptop.token(), "profile:read", "p").getReason());
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(laptop.token()));
        assertEquals(DenyReason.SESSION_REVOKED, ex.getReason());
        log.info("被结束会话 credentialId={} 判定依据=会话撤销位 -> SESSION_REVOKED（访问与刷新一致）",
                laptop.credentialId());

        // 同账号其余会话照常可用
        assertTrue(access.decide(phone.token(), "profile:read", "p").isAllowed());
        TokenResponse tabletV2 = auth.refresh(tablet.token());
        assertEquals(2L, tabletV2.version());

        // 已结束会话不能重新激活：时间推移后依旧拒绝，且原因稳定为撤销类
        clock.advance(10_000);
        AuthenticationException stillDead = assertThrows(AuthenticationException.class,
                () -> auth.refresh(laptop.token()));
        assertEquals(DenyReason.SESSION_REVOKED, stillDead.getReason());
        assertEquals(DenyReason.SESSION_REVOKED,
                access.decide(laptop.token(), "profile:read", "p").getReason());
        log.info("已结束会话 credentialId={} 判定依据=终止状态不可逆, 时间推移后仍 SESSION_REVOKED",
                laptop.credentialId());
    }

    @Test
    void unknownAccountListsEmptyAndReasonsMatchExistingStyle() {
        assertTrue(auth.listActiveSessions("ghost").isEmpty(), "未知账号返回空列表而非异常");
        TokenResponse phone = auth.login("alice", "pw");
        auth.revokeSession(phone.sessionId(), "logout");
        // 撤销一个不存在的会话：沿用既有 SESSION_NOT_FOUND 语义
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.revokeSession("no-such-session", "x"));
        assertEquals(DenyReason.SESSION_NOT_FOUND, ex.getReason());
        log.info("治理入口语义 credentialId=- 判定依据=未知账号空列表 / 未知会话 SESSION_NOT_FOUND，与既有风格一致");
    }
}
