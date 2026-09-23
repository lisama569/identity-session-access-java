package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.AttributeBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.access.DefaultAccessControlService;
import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
import com.github.lisama569.identitysessionaccessjava.access.RoleBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.audit.DefaultAuditService;
import com.github.lisama569.identitysessionaccessjava.auth.DefaultAuthService;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 访问判定测试：未认证/过期/轮换/撤销/权限不足原因可区分；
 * 角色与属性策略生效；降权与撤销对下一次判定立即生效（无缓存放行）。
 */
class AccessControlServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlServiceTest.class);
    private static final long TTL = 10_000L;

    private MutableTimeSource clock;
    private InMemoryUserStore users;
    private InMemorySessionStore sessionStore;
    private DefaultAuthService auth;
    private DefaultAccessControlService access;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeSource(5_000_000L);
        users = new InMemoryUserStore();
        sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-alice", "alice", hasher.hash("pw", "s1"), "s1",
                Set.of("USER"), Map.of("dept", "engineering", "level", "5"), true));
        users.save(new UserAccount("u-bob", "bob", hasher.hash("pw", "s2"), "s2",
                Set.of("USER", "AUDITOR"), Map.of("dept", "finance", "level", "3"), true));
        users.save(new UserAccount("u-admin", "admin", hasher.hash("pw", "s3"), "s3",
                Set.of("ADMIN"), Map.of("dept", "it", "level", "9"), true));
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        registry.register(new RoleBasedPolicy("reports:read", Set.of("AUDITOR", "ADMIN")));
        registry.register(new RoleBasedPolicy("admin:read", Set.of("ADMIN")));
        registry.register(new AttributeBasedPolicy("reports:read",
                (account, resource) -> "finance-reports".equals(resource)
                        && parseInt(account.getAttributes().get("level")) >= 5));
        DefaultAuditService audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokens = new LocalHmacTokenService("secret");
        auth = new DefaultAuthService(users, sessionStore, tokens, hasher, audit, clock, TTL);
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock);
    }

    private static int parseInt(String s) {
        try {
            return s == null ? 0 : Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void assertDeny(String token, String permission, String resource, DenyReason expected) {
        AuthDecision d = access.decide(token, permission, resource);
        assertFalse(d.isAllowed(), () -> "应被拒绝但被放行: " + expected);
        assertEquals(expected, d.getReason(),
                "拒绝原因不匹配: " + d.getMessage());
        log.info("访问判定 credentialId={} permission={} 判定依据={} -> {}",
                d.getCredentialId(), permission, expected, d.getMessage());
    }

    @Test
    void unauthenticatedAndUnknownAndMalformedAreDistinct() {
        assertDeny(null, "profile:read", "p", DenyReason.UNAUTHENTICATED);
        assertDeny("   ", "profile:read", "p", DenyReason.UNAUTHENTICATED);
        assertDeny("garbage.token", "profile:read", "p", DenyReason.UNAUTHENTICATED);
        // 签名合法但凭证标识不存在
        String forged = new LocalHmacTokenService("secret")
                .issueToken("nope-cred", "nope-sess", "u-alice", 1L);
        assertDeny(forged, "profile:read", "p", DenyReason.CREDENTIAL_NOT_FOUND);
    }

    @Test
    void roleAndAttributePoliciesAndDefaultDeny() {
        TokenResponse alice = auth.login("alice", "pw");
        TokenResponse bob = auth.login("bob", "pw");
        TokenResponse admin = auth.login("admin", "pw");

        assertTrue(access.decide(alice.token(), "profile:read", "p").isAllowed());
        // alice 非 AUDITOR/ADMIN，但 level=5 的 ABAC 规则允许其读财务报告
        assertTrue(access.decide(alice.token(), "reports:read", "finance-reports").isAllowed());
        // bob 虽有 AUDITOR 角色——等等，bob 是 AUDITOR，所以本就允许；改用 bob 访问管理资源验证 RBAC
        assertDeny(bob.token(), "admin:read", "admin-console", DenyReason.PERMISSION_DENIED);
        assertTrue(access.decide(admin.token(), "admin:read", "admin-console").isAllowed());
        // 不存在的权限：默认拒绝
        assertDeny(alice.token(), "delete:everything", "x", DenyReason.PERMISSION_DENIED);
        log.info("RBAC/ABAC 判定完成：alice 凭 ABAC(level>=5) 读财报，bob 访问 admin 资源 PERMISSION_DENIED");
    }

    @Test
    void expiredCredentialIsDeniedAtBoundary() {
        TokenResponse token = auth.login("alice", "pw");
        clock.advance(TTL);
        assertDeny(token.token(), "profile:read", "p", DenyReason.CREDENTIAL_EXPIRED);
    }

    @Test
    void rotatedCredentialReplayIsDeniedAsRotated() {
        TokenResponse first = auth.login("alice", "pw");
        TokenResponse second = auth.refresh(first.token());
        assertDeny(first.token(), "profile:read", "p", DenyReason.CREDENTIAL_ROTATED);
        assertTrue(access.decide(second.token(), "profile:read", "p").isAllowed());
    }

    @Test
    void sessionAndCredentialRevocationTakeEffectImmediately() {
        TokenResponse t1 = auth.login("alice", "pw");
        TokenResponse t2 = auth.login("bob", "pw");
        auth.revokeSession(t1.sessionId(), "logout");
        auth.revokeCredential(t2.credentialId(), "admin-kill");
        assertDeny(t1.token(), "profile:read", "p", DenyReason.SESSION_REVOKED);
        assertDeny(t2.token(), "profile:read", "p", DenyReason.CREDENTIAL_REVOKED);
    }

    @Test
    void demotionAndDisableTakeEffectOnNextDecisionWithoutCache() {
        TokenResponse token = auth.login("alice", "pw");
        assertTrue(access.decide(token.token(), "reports:read", "finance-reports").isAllowed());

        // 降权：直接修改账户属性（模拟管理端实时变更），下一次判定必须立即被权限拦截
        UserAccount alice = users.findByUsername("alice").orElseThrow();
        // UserAccount 的集合/Map 是不可变拷贝，这里通过重新落库模拟降权
        users.save(new UserAccount("u-alice", "alice", alice.getPasswordHash(),
                alice.getPasswordSalt(), Set.of("USER"),
                Map.of("dept", "engineering", "level", "1"), true));
        assertDeny(token.token(), "reports:read", "finance-reports",
                DenyReason.PERMISSION_DENIED);

        // 停用账户：下一次判定必须为 USER_DISABLED
        users.save(new UserAccount("u-alice", "alice", alice.getPasswordHash(),
                alice.getPasswordSalt(), Set.of("USER"),
                Map.of("dept", "engineering", "level", "1"), false));
        assertDeny(token.token(), "profile:read", "p", DenyReason.USER_DISABLED);
    }
}
