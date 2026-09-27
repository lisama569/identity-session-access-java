package com.github.lisama569.identitysessionaccessjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 真实 Spring 装配（真实系统时钟 + @Value 配置绑定）下的空闲超时端到端测试。
 *
 * <p>这里仅把时间窗口缩小以加速验证，<b>不改动任何代码或装配</b>：
 * 空闲窗口（700ms）严格短于凭证 TTL（60s）——与生产默认配置的关键关系
 * （默认空闲 10 分钟 &lt; 默认 TTL 15 分钟）完全同构。登录后保持无活动，
 * 访问入口与刷新入口都必须稳定返回 401 SESSION_IDLE_EXPIRED，
 * 而不是 CREDENTIAL_EXPIRED；治理列表也不再包含该会话。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "identity.session.ttl-millis=60000",
        "identity.session.idle-timeout-millis=700",
        "identity.session.max-active-sessions-per-account=5"
})
class WebIdleTimeoutIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebIdleTimeoutIntegrationTest.class);
    private final ObjectMapper json = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @Test
    void idleSessionIsRejectedOnBothHttpEntriesWithoutCustomConfig() throws Exception {
        MvcResult loginResult = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode login = json.readTree(loginResult.getResponse().getContentAsString());
        String token = login.get("token").asText();
        String sessionId = login.get("sessionId").asText();

        // 登录后完全不做任何操作，直到明显超过空闲窗口（700ms），但远未到 TTL（60s）
        Thread.sleep(900);

        // 访问入口：401 SESSION_IDLE_EXPIRED
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_IDLE_EXPIRED"));
        // 刷新入口：同一结论
        mvc.perform(post("/api/auth/refresh").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_IDLE_EXPIRED"));
        log.info("HTTP 默认装配空闲超时端到端 sessionId={} 访问/刷新均 401 SESSION_IDLE_EXPIRED",
                sessionId);

        // 空闲超时后不出现在账号活跃会话列表，旧凭证再试也无法复活
        mvc.perform(get("/api/auth/accounts/bob/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessions[?(@.sessionId=='" + sessionId + "')]").doesNotExist());
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_IDLE_EXPIRED"));
        log.info("HTTP 默认装配空闲会话已移出活跃列表且旧凭证不可复活 sessionId={}", sessionId);
    }
}
