package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.Application;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * 验证默认入口（Spring 装配）对“空闲窗口不短于凭证 TTL”的缺陷组合启动即失败。
 * 这是本仓库此前缺陷的根因（默认 idle=30min &gt; ttl=15min，空闲判定永远不可达），
 * 由 {@code DefaultAuthService} 的 {@code @PostConstruct} 配置自洽性校验兜底。
 */
class IdleTimeoutConfigValidationTest {

    @Test
    void contextFailsFastWhenIdleWindowNotShorterThanTtl() {
        SpringApplication app = new SpringApplication(Application.class);
        // 用最高优先级属性源覆盖打包在 jar 里的 application.properties，复刻缺陷组合
        app.addListeners((ApplicationEnvironmentPreparedEvent event) ->
                event.getEnvironment().getPropertySources().addFirst(new MapPropertySource(
                        "broken-idle-config", Map.of(
                        "spring.main.web-application-type", "none",
                        "spring.main.banner-mode", "off",
                        "identity.session.ttl-millis", "900000",
                        "identity.session.idle-timeout-millis", "1800000"))));
        try (var ignored = app.run()) {
            fail("idle(1800000) >= ttl(900000) 时应用必须启动失败");
        } catch (Exception expected) {
            StringBuilder chain = new StringBuilder(String.valueOf(expected.getMessage()));
            Throwable root = expected;
            while (root.getCause() != null) {
                root = root.getCause();
                chain.append(" | ").append(root.getMessage());
            }
            String text = chain.toString();
            assertTrue(text.contains("SESSION_IDLE_EXPIRED"),
                    "失败根因必须指向空闲超时不可达，实际：" + text);
        }
    }
}
