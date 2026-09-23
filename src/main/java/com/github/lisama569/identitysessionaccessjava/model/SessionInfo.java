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

    public SessionInfo(String id, String userId, String username, long createdAt, long ttlMillis,
                       String currentCredentialId, long currentVersion) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
        this.currentCredentialId = currentCredentialId;
        this.currentVersion = currentVersion;
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

    /**
     * 把会话当前指针从旧凭证原子地切换到新凭证。必须在会话级锁内调用。
     */
    public void rotate(String newCredentialId, long newVersion) {
        this.currentCredentialId = newCredentialId;
        this.currentVersion = newVersion;
    }

    /**
     * 标记会话被撤销。必须在会话级锁内调用；重复撤销保留首次原因（不互相覆盖）。
     */
    public void markRevoked(long at, String reason) {
        if (!this.revoked) {
            this.revoked = true;
            this.revokedAt = at;
            this.revokeReason = reason;
        }
    }
}
