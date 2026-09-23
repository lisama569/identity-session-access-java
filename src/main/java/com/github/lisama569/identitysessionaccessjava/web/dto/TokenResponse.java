package com.github.lisama569.identitysessionaccessjava.web.dto;

/** 登录/刷新成功后返回的短期会话凭证。 */
public record TokenResponse(
        String token,
        String sessionId,
        String credentialId,
        long version,
        long issuedAt,
        long expiresAt,
        long expiresInSeconds
) {
}
