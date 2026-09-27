package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 账号会话治理视图：描述一个活跃会话的关键状态，
 * 供“按账号查看当前活跃会话”的入口返回。
 *
 * @param sessionId           会话标识
 * @param userId              账号标识
 * @param username            账号名
 * @param issuedAt            会话签发时间（登录时刻）
 * @param lastActiveAt        最近活跃时间（登录 / 刷新成功 / 受保护访问通过时顺延）
 * @param currentVersion      当前凭证代次
 * @param currentCredentialId 当前有效凭证标识
 * @param currentExpiresAt    当前凭证的绝对过期时刻
 */
public record SessionView(
        String sessionId,
        String userId,
        String username,
        long issuedAt,
        long lastActiveAt,
        long currentVersion,
        String currentCredentialId,
        long currentExpiresAt
) {
}
