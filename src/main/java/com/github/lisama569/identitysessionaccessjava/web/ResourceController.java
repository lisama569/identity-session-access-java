package com.github.lisama569.identitysessionaccessjava.web;

import com.github.lisama569.identitysessionaccessjava.access.AccessControlService;
import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;
import com.github.lisama569.identitysessionaccessjava.web.dto.AccessResultView;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 受保护资源入口。每个入口都调用同一个 {@link AccessControlService#requireAllowed}，
 * 因此服务层直连、MockMvc、不同 URL 三条入口的结论与拒绝原因完全一致。
 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final AccessControlService accessControl;

    public ResourceController(AccessControlService accessControl) {
        this.accessControl = accessControl;
    }

    @GetMapping("/profile")
    public Map<String, Object> profile() {
        AuthDecision d = accessControl.requireAllowed(
                CurrentCredentialHolder.get(), "profile:read", "profile");
        return payload(d, Map.of("email", d.getUsername() + "@example.local",
                "profileOwner", d.getUsername()));
    }

    @GetMapping("/reports")
    public Map<String, Object> reports(@RequestParam(defaultValue = "finance-reports") String resource) {
        AuthDecision d = accessControl.requireAllowed(
                CurrentCredentialHolder.get(), "reports:read", resource);
        return payload(d, Map.of("reportRange", "2026-Q3", "resource", resource));
    }

    @GetMapping("/admin")
    public Map<String, Object> admin() {
        AuthDecision d = accessControl.requireAllowed(
                CurrentCredentialHolder.get(), "admin:read", "admin-console");
        return payload(d, Map.of("console", "admin-console", "operator", d.getUsername()));
    }

    @GetMapping("/engineering")
    public Map<String, Object> engineering() {
        AuthDecision d = accessControl.requireAllowed(
                CurrentCredentialHolder.get(), "engineering:read", "engineering-docs");
        return payload(d, Map.of("docs", "engineering-docs", "viewer", d.getUsername()));
    }

    /**
     * 通用判定回显入口：不抛异常，直接返回可解释结论（allowed + reason + 凭证标识），
     * 便于对同一套判定做端到端验证。
     */
    @GetMapping("/check/{permission}")
    public AccessResultView explicitCheck(@PathVariable String permission,
                                          @RequestParam(defaultValue = "") String resource) {
        AuthDecision d = accessControl.decide(CurrentCredentialHolder.get(), permission,
                resource.isEmpty() ? permission : resource);
        return new AccessResultView(d.isAllowed(),
                d.getReason() == null ? null : d.getReason().name(), d.getMessage(),
                d.getUsername(), d.getSessionId(), d.getCredentialId(),
                d.getPermission(), d.getResource());
    }

    static Map<String, Object> payload(AuthDecision d) {
        return payload(d, Map.of());
    }

    static Map<String, Object> payload(AuthDecision d, Map<String, ?> data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access", Map.of(
                "allowed", true,
                "subject", d.getUsername(),
                "sessionId", d.getSessionId(),
                "credentialId", d.getCredentialId(),
                "permission", d.getPermission(),
                "resource", d.getResource()));
        body.put("data", data);
        return body;
    }
}
