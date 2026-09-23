package com.github.lisama569.identitysessionaccessjava.auth.web;

import com.github.lisama569.identitysessionaccessjava.auth.exception.AuthDenyException;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static com.github.lisama569.identitysessionaccessjava.auth.web.ApiModels.ErrorView;

/**
 * 将可区分的拒绝原因映射为可区分的 HTTP 状态码与响应体原因码。
 *
 * <p>映射约定：</p>
 * <ul>
 *   <li>BAD_CREDENTIALS / UNKNOWN TOKEN → 401</li>
 *   <li>TOKEN_EXPIRED → 401（reason 区分过期）</li>
 *   <li>TOKEN_ROTATED / CONCURRENTLY_ROTATED → 409（凭证已被轮换/并发竞争失败）</li>
 *   <li>TOKEN_REVOKED / SESSION_REVOKED / USER_DISABLED → 403</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AuthDenyException.class)
    public ResponseEntity<ErrorView> handle(AuthDenyException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case BAD_CREDENTIALS, UNAUTHENTICATED, TOKEN_EXPIRED -> HttpStatus.UNAUTHORIZED;
            case TOKEN_ROTATED, CONCURRENTLY_ROTATED -> HttpStatus.CONFLICT;
            case TOKEN_REVOKED, SESSION_REVOKED, USER_DISABLED -> HttpStatus.FORBIDDEN;
            case INSUFFICIENT_PERMISSIONS -> HttpStatus.FORBIDDEN;
        };
        return ResponseEntity.status(status).body(new ErrorView(
                "access_denied",
                ex.getReason() == null ? null : ex.getReason().name(),
                ex.getTokenId()));
    }
}
