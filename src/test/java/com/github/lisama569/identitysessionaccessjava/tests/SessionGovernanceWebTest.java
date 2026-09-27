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
 * 多设备会话治理 HTTP 端到端：按账号列出活跃会话、定向结束单设备、
 * 容量淘汰与空闲超时在默认入口上的状态码与机器可读原因沿用既有约定（401 + reason）。
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "identity.session.idle-timeout-millis=300")
class SessionGovernanceWebTest {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceWebTest.class);
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
    void listTerminateAndCapacityEvictionWorkOverHttp() throws Exception {
        // 三台设备登录
        JsonNode phone = login("bob", "bob-pass");
        JsonNode laptop = login("bob", "bob-pass");
        JsonNode tablet = login("bob", "bob-pass");

        MvcResult listResult = mvc.perform(get("/api/auth/accounts/bob/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessionCount").value(3))
                .andExpect(jsonPath("$.sessions[0].issuedAt").exists())
                .andExpect(jsonPath("$.sessions[0].lastActiveAt").exists())
                .andExpect(jsonPath("$.sessions[0].currentVersion").value(1))
                .andReturn();
        log.info("HTTP 列出活跃会话 activeSessionCount=3（含签发时间/最近活跃/凭证代次）: {}",
                listResult.getResponse().getContentAsString());

        // 只结束 laptop 一个设备
        mvc.perform(post("/api/auth/sessions/" + laptop.get("sessionId").asText() + "/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"kick-device\"}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/auth/accounts/bob/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessionCount").value(2));
        mvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + laptop.get("token").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        // 其余设备照常
        mvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + phone.get("token").asText()))
                .andExpect(status().isOk());
        mvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + tablet.get("token").asText()))
                .andExpect(status().isOk());
        log.info("HTTP 定向结束 sessionId={}：该设备 SESSION_REVOKED，其余设备 200",
                laptop.get("sessionId").asText());

        // 容量淘汰：默认上限 5。laptop 已撤销，当前活跃 2（phone/tablet）；
        // 再登录 4 个使活跃数达到 6 > 5，最久未活跃的 phone 被淘汰
        login("bob", "bob-pass");
        login("bob", "bob-pass");
        login("bob", "bob-pass");
        JsonNode seventh = login("bob", "bob-pass");
        mvc.perform(get("/api/auth/accounts/bob/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessionCount").value(5));
        mvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + phone.get("token").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_CAPACITY_EVICTED"));
        mvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Bearer " + phone.get("token").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_CAPACITY_EVICTED"));
        // 最新会话不受影响
        mvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + seventh.get("token").asText()))
                .andExpect(status().isOk());
        log.info("HTTP 容量淘汰 credentialId={} -> 401 SESSION_CAPACITY_EVICTED，新会话照常 200",
                phone.get("credentialId").asText());
    }

    @Test
    void idleTimeoutIsReportedOverHttpWithDistinctReason() throws Exception {
        JsonNode t = login("alice", "alice-pass");
        // 空闲上限 300ms：不做任何活动，等待越过边界
        Thread.sleep(600);
        mvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + t.get("token").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_IDLE_TIMEOUT"));
        mvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Bearer " + t.get("token").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_IDLE_TIMEOUT"));
        log.info("HTTP 空闲超时 credentialId={} -> 401 SESSION_IDLE_TIMEOUT（与 CREDENTIAL_EXPIRED 区分）",
                t.get("credentialId").asText());
    }
}
