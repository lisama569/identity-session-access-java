package com.github.lisama569.identitysessionaccessjava.web;

import com.github.lisama569.identitysessionaccessjava.access.AuthorizationException;
import com.github.lisama569.identitysessionaccessjava.auth.AuthenticationException;
import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.time.TimeSource;
import com.github.lisama569.identitysessionaccessjava.web.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 把可区分的拒绝原因映射为稳定的 HTTP 状态与错误体。
 *
 * <p>约定：认证类问题 401（凭证缺失/无效/过期/轮换/并发失效）；
 * 已撤销使用 401 但 reason 可区分；权限不足 403。</p>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final TimeSource timeSource;

    public GlobalExceptionHandler(TimeSource timeSource) {
        this.timeSource = timeSource;
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuth(AuthenticationException ex) {
        ErrorResponse body = new ErrorResponse(false, ex.getReason(), ex.getMessage(),
                null, ex.getCredentialId(), timeSource.nowMillis());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<ErrorResponse> handleAccess(AuthorizationException ex) {
        AuthDecision d = ex.getDecision();
        HttpStatus status = d.getReason() == DenyReason.PERMISSION_DENIED
                ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED;
        ErrorResponse body = new ErrorResponse(false, d.getReason(), d.getMessage(),
                d.getResource(), d.getCredentialId(), timeSource.nowMillis());
        return ResponseEntity.status(status).body(body);
    }
}
