package com.github.lisama569.identitysessionaccessjava.web;

import com.github.lisama569.identitysessionaccessjava.auth.AuthService;
import com.github.lisama569.identitysessionaccessjava.model.SessionView;
import com.github.lisama569.identitysessionaccessjava.web.dto.LoginRequest;
import com.github.lisama569.identitysessionaccessjava.web.dto.RevokeRequest;
import com.github.lisama569.identitysessionaccessjava.web.dto.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 登录 / 刷新轮换 / 撤销入口。刷新必须凭 Bearer 头中的当前有效凭证；
 * 成功后旧凭证在服务端事务提交之时立即失效。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenResponse login(@RequestBody LoginRequest request) {
        String username = request == null ? null : request.username();
        String password = request == null ? null : request.password();
        return authService.login(username, password);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh() {
        // 未携带凭证时由 AccessControl 同款原因码表达：这里交由服务判定为 CREDENTIAL_NOT_FOUND
        return authService.refresh(CurrentCredentialHolder.get());
    }

    /**
     * 按账号查看当前活跃会话：列出未撤销、未过期的会话，
     * 含签发时间、最近活跃时间与当前凭证代次。
     */
    @GetMapping("/accounts/{username}/sessions")
    public Map<String, Object> listAccountSessions(@PathVariable String username) {
        List<SessionView> sessions = authService.listActiveSessions(username);
        return Map.of(
                "username", username,
                "activeSessionCount", sessions.size(),
                "sessions", sessions);
    }

    @PostMapping("/sessions/{sessionId}/revoke")
    public Map<String, Object> revokeSession(@PathVariable String sessionId,
                                             @RequestBody(required = false) RevokeRequest request) {
        String reason = request == null || request.reason() == null
                ? "user-logout" : request.reason();
        authService.revokeSession(sessionId, reason);
        return Map.of(
                "revoked", true,
                "scope", "SESSION",
                "sessionId", sessionId,
                "propagation", "同步即时：撤销在会话锁内提交，后续任何访问/刷新立即拒绝");
    }

    @PostMapping("/credentials/{credentialId}/revoke")
    public Map<String, Object> revokeCredential(@PathVariable String credentialId,
                                                @RequestBody(required = false) RevokeRequest request) {
        String reason = request == null || request.reason() == null
                ? "admin-revoke" : request.reason();
        authService.revokeCredential(credentialId, reason);
        return Map.of(
                "revoked", true,
                "scope", "CREDENTIAL",
                "credentialId", credentialId,
                "propagation", "同步即时：后续任何携带该凭证的访问立即拒绝");
    }
}
