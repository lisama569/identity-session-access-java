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
 * 默认配置可复现性测试：不传入任何自定义空闲/有效期参数，服务一律通过
 * “兼容构造器”取代码内默认值（与 application.properties 的默认入口一致）。
 *
 * <p>该用例守护的核心不变量：<b>默认空闲窗口必须严格短于默认凭证 TTL</b>，
 * 否则完全无活动的会话会先撞绝对有效期，默认启动方式下永远看不到
 * SESSION_IDLE_EXPIRED（本仓库此前的缺陷）。</p>
 */
class DefaultIdleTimeoutConfigTest {

    private static final Logger log = LoggerFactory.getLogger(DefaultIdleTimeoutConfigTest.class);

    /** 与 application.properties / @Value 占位默认保持一致的基准值（仅用于断言与推进时钟）。 */
    private static final long DEFAULT_TTL_MILLIS = 900_000L;
    private static final long DEFAULT_IDLE_MILLIS =
            DefaultAuthService.DEFAULT_IDLE_TIMEOUT_MILLIS;

    private MutableTimeSource clock;
    private DefaultAuthService auth;
    private DefaultAccessControlService access;

    @BeforeEach
    void setUp() {
        // 前置条件：默认空闲窗口必须可在绝对有效期内到达，否则空闲判定默认可达性不成立
        assertTrue(DEFAULT_IDLE_MILLIS < DEFAULT_TTL_MILLIS,
                "默认空闲窗口 " + DEFAULT_IDLE_MILLIS + "ms 必须短于默认凭证 TTL "
                        + DEFAULT_TTL_MILLIS + "ms，否则默认入口看不到空闲超时");
        clock = new MutableTimeSource(10_000_000L);
        InMemoryUserStore users = new InMemoryUserStore();
        InMemorySessionStore sessionStore = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        users.save(new UserAccount("u-1", "alice", hasher.hash("pw", "salt"), "salt",
                Set.of("USER"), Map.of(), true));
        DefaultAuditService audit = new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokens = new LocalHmacTokenService("test-secret");
        // 兼容构造：TTL 显式给默认值，空闲窗口走代码默认值（测试不做任何额外配置）
        auth = new DefaultAuthService(users, sessionStore, tokens, hasher, audit, clock,
                DEFAULT_TTL_MILLIS);
        PolicyRegistry registry = new PolicyRegistry();
        registry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        // 兼容构造：空闲窗口同样走代码默认值
        access = new DefaultAccessControlService(tokens, sessionStore, users, registry,
                audit, clock);
    }

    @Test
    void idleTimeoutIsReachableBeforeAbsoluteExpiryUnderDefaults() {
        TokenResponse t = auth.login("alice", "pw");

        // 一直不做任何操作，推进到“明显超过空闲窗口、但远未到绝对有效期”
        clock.advance(DEFAULT_IDLE_MILLIS + 60_000L);
        assertTrue(clock.nowMillis() < t.expiresAt(),
                "此刻必须仍在凭证绝对有效期内，否则无法区分空闲与绝对过期");

        // 访问入口：SESSION_IDLE_EXPIRED（而不是 CREDENTIAL_EXPIRED）
        AuthDecision denied = access.decide(t.token(), "profile:read", "profile");
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, denied.getReason());
        // 刷新入口：结论一致
        AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> auth.refresh(t.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex.getReason());
        log.info("默认配置下空闲超时可达 credential={} now={} expiresAt={} idle={}ms "
                        + "判定依据=默认空闲窗口短于默认 TTL, 访问与刷新均 SESSION_IDLE_EXPIRED",
                t.credentialId(), clock.nowMillis(), t.expiresAt(), DEFAULT_IDLE_MILLIS);

        // 空闲超时后从活跃会话治理列表消失
        List<SessionView> active = auth.listActiveSessions("alice");
        assertTrue(active.stream().noneMatch(v -> v.sessionId().equals(t.sessionId())),
                "已空闲超时的会话不应再出现在活跃会话列表");

        // 旧凭证无法把会话“复活”：再次访问/刷新依旧是空闲超时
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(t.token(), "profile:read", "profile").getReason());
        assertThrows(AuthenticationException.class, () -> auth.refresh(t.token()));
    }

    @Test
    void idleBoundaryIsExactUnderDefaults() {
        TokenResponse t = auth.login("alice", "pw");

        // 恰在空闲边界（相等）：超时（含等于）
        clock.advance(DEFAULT_IDLE_MILLIS);
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED,
                access.decide(t.token(), "profile:read", "profile").getReason());
        assertThrows(AuthenticationException.class,
                () -> auth.refresh(t.token()));
        log.info("默认配置空闲边界（相等即超时）credential={} now-lastActiveAt={}ms",
                t.credentialId(), DEFAULT_IDLE_MILLIS);
    }

    @Test
    void activeSessionSurvivesUntilAbsoluteExpiryUnderDefaults() {        TokenResponse t = auth.login("alice", "pw");

        // 持续活动（每 9 分钟访问一次，默认空闲窗口 10 分钟），直到绝对有效期前仍可用
        long step = DEFAULT_IDLE_MILLIS - 60_000L;
        while (clock.nowMillis() + step < t.expiresAt()) {
            clock.advance(step);
            assertTrue(access.decide(t.token(), "profile:read", "profile").isAllowed(),
                    "窗口内持续活动的会话应保持可用");
        }
        // 到达绝对有效期：原因是绝对过期，而非空闲
        clock.set(t.expiresAt());
        assertEquals(DenyReason.CREDENTIAL_EXPIRED,
                access.decide(t.token(), "profile:read", "profile").getReason());
        log.info("默认配置持续活跃至绝对过期 credential={} 判定依据=CREDENTIAL_EXPIRED 与空闲区分",
                t.credentialId());
    }

    @Test
    void idleWindowNotShorterThanTtlIsRejectedAtStartup() {
        // 复刻缺陷配置：空闲窗口 >= 凭证 TTL —— 空闲判定不可达。
        // 构造器允许直连测试自由组合，但 Spring 生命周期校验（默认入口）必须拒绝。
        InMemoryUserStore users = new InMemoryUserStore();
        InMemorySessionStore store = new InMemorySessionStore();
        PasswordHasher hasher = new PasswordHasher();
        DefaultAuditService auditService =
                new DefaultAuditService(new InMemoryAuditStore(), clock);
        LocalHmacTokenService tokenService = new LocalHmacTokenService("test-secret");

        DefaultAuthService equal = new DefaultAuthService(users, store, tokenService, hasher,
                auditService, clock, 900_000L, 5, 900_000L);
        IllegalStateException exEqual = assertThrows(IllegalStateException.class,
                equal::validateIdleWindowShorterThanTtl);
        assertTrue(exEqual.getMessage().contains("SESSION_IDLE_EXPIRED"));

        DefaultAuthService larger = new DefaultAuthService(users, store, tokenService, hasher,
                auditService, clock, 900_000L, 5, 1_800_000L);
        IllegalStateException exLarger = assertThrows(IllegalStateException.class,
                larger::validateIdleWindowShorterThanTtl);
        assertTrue(exLarger.getMessage().contains("1800000"));
        log.info("缺陷配置（idle>=ttl）在默认入口启动校验即拒绝，避免空闲超时不可达");

        // 默认组合（10min < 15min）校验通过
        DefaultAuthService defaults = new DefaultAuthService(users, store, tokenService, hasher,
                auditService, clock, DEFAULT_TTL_MILLIS);
        defaults.validateIdleWindowShorterThanTtl();
    }
}
