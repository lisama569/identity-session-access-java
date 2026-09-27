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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 入口端到端测试：登录、各资源入口的拒绝原因与服务层一致；
 * 轮换旧凭证、撤销后访问都在真实 Web 链路上得到可区分结论。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTest.class);
    private final ObjectMapper json = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    private JsonNode login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return json.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void unauthenticatedAndBadLoginAndPermissionDenyAreConsistentAcrossEntries() throws Exception {
        // 无令牌访问受保护入口：全部 401 + UNAUTHENTICATED（各入口同一判定）
        for (String path : new String[]{"/api/resources/profile", "/api/resources/reports",
                "/api/resources/admin"}) {
            mvc.perform(get(path))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
        }
        // check 入口不抛异常，回显结论：HTTP 200 + allowed=false + UNAUTHENTICATED
        mvc.perform(get("/api/resources/check/profile:read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
        log.info("多入口一致性：无凭证访问 profile/reports/admin/check 全部 UNAUTHENTICATED");

        // 错误口令：401 + BAD_CREDENTIALS
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"nope\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("BAD_CREDENTIALS"));

        JsonNode alice = login("alice", "alice-pass");
        String token = alice.get("token").asText();
        String sessionId = alice.get("sessionId").asText();

        // alice 可读 profile，不可读 admin（403 PERMISSION_DENIED）
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access.allowed").value(true));
        mvc.perform(get("/api/resources/admin").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("PERMISSION_DENIED"));
        log.info("credentialId={} profile 放行 / admin 403 PERMISSION_DENIED",
                alice.get("credentialId").asText());

        // check 入口回显可解释结论（不抛异常，HTTP 200 + allowed=false）
        mvc.perform(get("/api/resources/check/admin:read")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.reason").value("PERMISSION_DENIED"))
                .andExpect(jsonPath("$.credentialId").value(alice.get("credentialId").asText()));
    }

    @Test
    void refreshRotationAndSessionRevocationPropagateEndToEnd() throws Exception {
        JsonNode alice = login("alice", "alice-pass");
        String token1 = alice.get("token").asText();
        String sessionId = alice.get("sessionId").asText();

        // 轮换
        MvcResult refreshResult = mvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Bearer " + token1))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode second = json.readTree(refreshResult.getResponse().getContentAsString());
        String token2 = second.get("token").asText();

        // 旧凭证立即失效：401 CREDENTIAL_ROTATED
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token1))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_ROTATED"));
        // 新凭证可用
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token2))
                .andExpect(status().isOk());
        log.info("轮换端到端：旧 credentialId={} -> CREDENTIAL_ROTATED，新 credentialId={} 可用",
                alice.get("credentialId").asText(), second.get("credentialId").asText());

        // 撤销会话
        mvc.perform(post("/api/auth/sessions/" + sessionId + "/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"e2e-logout\"}"))
                .andExpect(status().isOk());
        // 撤销后新凭证立即不可用：401 SESSION_REVOKED
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token2))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        // 撤销后刷新同样被拒
        mvc.perform(post("/api/auth/refresh").header("Authorization", "Bearer " + token2))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        log.info("撤销传播端到端：sessionId={} 撤销后访问与刷新均 SESSION_REVOKED", sessionId);

        // 审计可按会话查询
        mvc.perform(get("/api/audit/events/session/" + sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.type=='SESSION_REVOKED')]").exists());
    }

    @Test
    void disabledUserCannotLogin() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"carol\",\"password\":\"carol-pass\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("USER_DISABLED"));
    }

    @Test
    void accountSessionGovernanceEndToEnd() throws Exception {
        // 同一账号两个设备登录（用 bob，避免与本类其他用例的 alice 会话互相计入容量）
        JsonNode device1 = login("bob", "bob-pass");
        JsonNode device2 = login("bob", "bob-pass");
        String token1 = device1.get("token").asText();
        String token2 = device2.get("token").asText();
        String session1 = device1.get("sessionId").asText();
        String session2 = device2.get("sessionId").asText();

        // 按账号查看活跃会话：两个会话都在，含签发时间/最近活跃时间/凭证代次
        mvc.perform(get("/api/auth/accounts/bob/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessionCount").value(2))
                .andExpect(jsonPath("$.sessions[?(@.sessionId=='" + session1 + "')].issuedAt").exists())
                .andExpect(jsonPath("$.sessions[?(@.sessionId=='" + session1 + "')].lastActiveAt").exists())
                .andExpect(jsonPath("$.sessions[?(@.sessionId=='" + session1 + "')].currentVersion").exists());
        log.info("治理视图端到端：账号 bob 活跃会话=2, session1={} session2={}", session1, session2);

        // 定向结束设备 1：其凭证立即失效（401 SESSION_REVOKED），设备 2 照常可用
        mvc.perform(post("/api/auth/sessions/" + session1 + "/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"kick-one-device\"}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token1))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        mvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + token2))
                .andExpect(status().isOk());
        log.info("定向结束端到端：session1={} 访问->401 SESSION_REVOKED, session2={} 仍可用",
                session1, session2);

        // 治理视图收敛为 1 个活跃会话
        mvc.perform(get("/api/auth/accounts/bob/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessionCount").value(1))
                .andExpect(jsonPath("$.sessions[0].sessionId").value(session2));
    }
}
