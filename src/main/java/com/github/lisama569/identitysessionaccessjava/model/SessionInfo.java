package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 会话。会话持有当前有效凭证 id；会话撤销是“根撤销”，
 * 其名下所有凭证（含已轮换的旧凭证）一并失效。
 *
 * <p><b>并发契约：</b>{@link #rotate} 与 {@link #markRevoked} 只能在
 * {@code SessionStore} 的会话级锁内调用；读取（含 currentCredentialId、
 * revoked 等 volatile 字段）可以在锁外进行。</p>
 */
public final class SessionInfo {
    private final String id;
    private final String userId;
    private final String username;
    private final long createdAt;
    private final long ttlMillis;
    private volatile String currentCredentialId;
    private volatile long currentVersion;
    private volatile boolean revoked;
    private volatile long revokedAt;
    private volatile String revokeReason;
    private volatile RevokeKind revokeKind = RevokeKind.NONE;
    /** 最近活跃时间：登录时等于 createdAt；刷新成功、受保护访问通过时顺延。 */
    private volatile long lastActiveAt;

    public SessionInfo(String id, String userId, String username, long createdAt, long ttlMillis,
                       String currentCredentialId, long currentVersion) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
        this.currentCredentialId = currentCredentialId;
        this.currentVersion = currentVersion;
        this.lastActiveAt = createdAt;
    }

    public String getId() { return id; }
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public long getCreatedAt() { return createdAt; }
    public long getTtlMillis() { return ttlMillis; }
    public String getCurrentCredentialId() { return currentCredentialId; }
    public long getCurrentVersion() { return currentVersion; }
    public boolean isRevoked() { return revoked; }
    public long getRevokedAt() { return revokedAt; }
    public String getRevokeReason() { return revokeReason; }
    public RevokeKind getRevokeKind() { return revokeKind; }
    public long getLastActiveAt() { return lastActiveAt; }

    /**
     * 记录一次活动（刷新成功 / 受保护访问通过），顺延空闲窗口。
     * 单调推进：并发活动下不允许 lastActiveAt 回退。
     */
    public void touch(long at) {
        if (at > this.lastActiveAt) {
            this.lastActiveAt = at;
        }
    }

    /** 空闲判定：now - lastActiveAt >= idleTimeoutMillis 即视为空闲超时（含边界）。 */
    public boolean isIdleExpiredAt(long now, long idleTimeoutMillis) {
        return now - lastActiveAt >= idleTimeoutMillis;
    }

    /**
     * 把会话当前指针从旧凭证原子地切换到新凭证。必须在会话级锁内调用。
     */
    public void rotate(String newCredentialId, long newVersion) {
        this.currentCredentialId = newCredentialId;
        this.currentVersion = newVersion;
    }

    /**
     * 标记会话被撤销（显式撤销）。必须在会话级锁内调用；重复撤销保留首次原因（不互相覆盖）。
     */
    public void markRevoked(long at, String reason) {
        markRevoked(at, reason, RevokeKind.EXPLICIT);
    }

    /**
     * 标记会话被结束，并记录结束类别（显式撤销 / 容量淘汰）。
     * 必须在会话级锁内调用；重复结束保留首次类别与原因（不互相覆盖）。
     */
    public void markRevoked(long at, String reason, RevokeKind kind) {
        if (!this.revoked) {
            this.revoked = true;
            this.revokedAt = at;
            this.revokeReason = reason;
            this.revokeKind = kind;
        }
    }
}
