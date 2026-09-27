package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.access.AccessControlService;
import com.github.lisama569.identitysessionaccessjava.auth.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * “按仓库现有默认配置直接启动、不额外调整任何配置”的守护测试：
 * application.properties 中的空闲窗口必须严格短于凭证 TTL，
 * 默认入口下空闲超时才会先于绝对过期发生。
 *
 * <p>同时读取两个服务实际装配的参数，防止属性键改名或缺省值漂移后
 * 又回到“默认入口只看得到绝对过期、看不到空闲超时”的状态。</p>
 */
@SpringBootTest
class IdleTimeoutDefaultPropertiesTest {

    @Autowired
    private Environment env;

    @Autowired
    private AuthService authService;

    @Autowired
    private AccessControlService accessControlService;

    private static long readField(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return (long) f.get(target);
    }

    @Test
    void defaultPropertiesMakeIdleWindowShorterThanTtl() {
        long idle = Long.parseLong(env.getProperty("identity.session.idle-timeout-millis"));
        long ttl = Long.parseLong(env.getProperty("identity.session.ttl-millis"));
        assertEquals(600_000L, idle,
                "application.properties 默认空闲窗口应为 600000ms（10 分钟）");
        assertEquals(900_000L, ttl,
                "application.properties 默认凭证 TTL 应为 900000ms（15 分钟）");
        assertTrue(idle < ttl,
                "默认配置下空闲窗口必须严格短于凭证 TTL，空闲超时才默认可达");
    }

    @Test
    void bothEntriesAreWiredWithTheSameShorterIdleWindow() throws Exception {
        long authIdle = readField(authService, "idleTimeoutMillis");
        long authTtl = readField(authService, "ttlMillis");
        long accessIdle = readField(accessControlService, "idleTimeoutMillis");
        assertEquals(600_000L, authIdle);
        assertEquals(authIdle, accessIdle, "访问入口与刷新入口必须使用同一空闲窗口");
        assertTrue(authIdle < authTtl, "装配后的空闲窗口必须严格短于凭证 TTL");
    }
}
