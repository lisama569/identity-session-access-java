package com.github.lisama569.identitysessionaccessjava.web.dto;

/** 会话治理视图：账号名下某个活跃会话的关键状态。 */
public record SessionView(
        String sessionId,
        String username,
        long issuedAt,
        long lastActiveAt,
        long currentVersion,
        String currentCredentialId,
        long currentCredentialExpiresAt
) {
}
