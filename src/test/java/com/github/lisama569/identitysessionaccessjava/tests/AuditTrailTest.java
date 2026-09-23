package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.DefaultAccessControlService;
import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
import com.github.lisama569.identitysessionaccessjava.audit.AuditService;
import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.AuditEvent;
import com.github.lisama569.identitysessionaccessjava.model.AuditEventType;
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

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 审计链路测试：登录成功/失败、刷新成功/失败、访问允许/拒绝、会话/凭证撤销
 * 全部产生可追溯事件，事件顺序编号且按会话可串联完整生命周期。
 */
class AuditTrailTest {

    private static final Logger log = LoggerFactory.getLogger(AuditTrailTest.class);

    private MutableTimeSource clock;
    private DefaultAuthService auth;
    private DefaultAccessControlService access;
    private AuditService audit;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(7_000_000L);
        InMemoryUserStore users = new InMemoryUserStore();
        InMemorySessionStore sessions = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of("dept", "engineering"), true));
        audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokens = new LocalHmacTokenService("secret");
        auth = new DefaultAuthService(users, sessions, tokens, hasher, audit, clock, 60_000L);
        access = new DefaultAccessControlService(tokens, sessions, users,
                new PolicyRegistry(), audit, clock);
    }

    @Test
    void fullLifecycleLeavesTraceableChain() {
        assertThrows(AuthenticationException.class, () -> auth.login("alice", "wrong"));
        TokenResponse t1 = auth.login("alice", "pw");
        TokenResponse t2 = auth.refresh(t1.token());

        // 一次允许、一次权限不足、一次旧凭证重放、一次撤销
        access.decide(t2.token(), "anything:read", "r");
        access.decide(t1.token(), "anything:read", "r");
        auth.revokeSession(t1.sessionId(), "audit-test-logout");

        List<AuditEvent> chain = audit.bySession(t1.sessionId());
        List<AuditEventType> types = chain.stream().map(AuditEvent::type).toList();
        log.info("会话审计链路 sessionId={} types={}", t1.sessionId(), types);

        assertTrue(types.contains(AuditEventType.LOGIN_SUCCESS));
        assertTrue(types.contains(AuditEventType.REFRESH_SUCCESS));
        assertTrue(types.contains(AuditEventType.ACCESS_DENIED));
        assertTrue(types.contains(AuditEventType.SESSION_REVOKED));
        assertTrue(types.contains(AuditEventType.CREDENTIAL_REVOKED));

        // 旧凭证重放的拒绝事件必须带凭证标识且原因确定
        AuditEvent replayDeny = chain.stream()
                .filter(e -> e.credentialId().equals(t1.credentialId())
                        && e.type() == AuditEventType.ACCESS_DENIED)
                .findFirst().orElseThrow();
        assertEquals(DenyReason.CREDENTIAL_ROTATED, replayDeny.reason());
        assertNotNull(replayDeny.eventId());

        // 撤销后访问也有记录，原因为会话撤销
        access.decide(t2.token(), "anything:read", "r");
        AuditEvent revokedDeny = audit.bySession(t1.sessionId()).stream()
                .filter(e -> e.type() == AuditEventType.ACCESS_DENIED
                        && e.reason() == DenyReason.SESSION_REVOKED)
                .findFirst().orElseThrow();
        assertEquals(t2.credentialId(), revokedDeny.credentialId());

        // 事件 id 严格递增、只增不改
        List<AuditEvent> all = audit.all();
        for (int i = 1; i < all.size(); i++) {
            assertTrue(all.get(i).eventId() > all.get(i - 1).eventId());
        }
        log.info("审计结论：事件数={} 顺序编号，凭证标识与判定原因完整可追溯", all.size());
    }

    @Test
    void loginFailureIsAudited() {
        assertThrows(AuthenticationException.class, () -> auth.login("ghost", "pw"));
        AuditEvent failure = audit.all().stream()
                .filter(e -> e.type() == AuditEventType.LOGIN_FAILURE)
                .findFirst().orElseThrow();
        assertEquals(DenyReason.BAD_CREDENTIALS, failure.reason());
        assertEquals("ghost", failure.subject());
    }
}
