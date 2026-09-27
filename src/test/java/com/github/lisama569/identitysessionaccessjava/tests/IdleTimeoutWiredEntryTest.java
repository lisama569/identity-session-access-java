package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.AccessControlService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.web.dto.TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 真实 Spring 链路（默认 SystemTimeSource）下的空闲超时行为：
 * 仅把空闲窗口通过启动参数调小（仍严格短于默认 TTL），登录后不做任何操作，
 * 超过空闲窗口但远未到绝对有效期时，访问入口与刷新入口结论一致为
 * SESSION_IDLE_EXPIRED，而不是 CREDENTIAL_EXPIRED。
 *
 * <p>这等价于手工冒烟“等待超过空闲窗口”的步骤，只是用属性把 10 分钟缩短到
 * 100ms 以便自动化；判定路径与默认入口完全相同。</p>
 */
@SpringBootTest(properties = {
        "identity.session.idle-timeout-millis=100",
        "identity.session.ttl-millis=900000"
})
class IdleTimeoutWiredEntryTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private AccessControlService accessControlService;

    @Test
    void idleExpiryIsObservedOnBothEntriesBeforeAbsoluteExpiry() throws Exception {
        TokenResponse token = authService.login("alice", "alice-pass");
        Thread.sleep(120L); // 明显超过 100ms 空闲窗口，但距 15 分钟绝对有效期极远
        assertTrue(System.currentTimeMillis() < token.expiresAt(),
                "此时绝不应到达凭证绝对有效期");

        AuthDecision decision = accessControlService.decide(token.token(), "profile:read",
                "profile");
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, decision.getReason());

        AuthenticationException ex = org.junit.jupiter.api.Assertions.assertThrows(
                AuthenticationException.class, () -> authService.refresh(token.token()));
        assertEquals(DenyReason.SESSION_IDLE_EXPIRED, ex.getReason());
    }
}
