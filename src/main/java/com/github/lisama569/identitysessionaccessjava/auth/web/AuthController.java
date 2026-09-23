package com.github.lisama569.identitysessionaccessjava.auth.web;

import com.github.lisama569.identitysessionaccessjava.auth.model.IssuedCredential;
import com.github.lisama569.identitysessionaccessjava.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.github.lisama569.identitysessionaccessjava.auth.web.ApiModels.*;

/**
 * 登录、刷新/轮换、撤销入口。
 *
 * <p>所有拒绝均以可区分原因抛出 {@code AuthDenyException}，由
 * {@link ApiExceptionHandler} 统一映射；成功响应携带凭证标识 tokenId（非凭证本体
 * 之外的可观测 ID），便于在日志与审计中对齐凭证生命周期。</p>
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<CredentialView> login(@RequestBody LoginRequest request) {
        IssuedCredential issued = authService.login(request.username(), request.password());
        return ResponseEntity.ok(toView(issued));
    }

    @PostMapping("/refresh")
    public CredentialView refresh(@RequestBody RefreshRequest request) {
        return toView(authService.refresh(request.token()));
    }

    @PostMapping("/revoke")
    public Map<String, Object> revoke(@RequestBody RevokeRequest request) {
        authService.revokeToken(request.token(), request.reason());
        return Map.of("revoked", true, "reason", request.reason() == null ? "" : request.reason());
    }

    private static CredentialView toView(IssuedCredential c) {
        return new CredentialView(c.token(), c.tokenId(), c.sessionId(),
                c.serial(), c.issuedAt(), c.expiresAt());
    }
}
