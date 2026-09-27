package com.github.lisama569.identitysessionaccessjava.model;

import java.util.concurrent.atomic.AtomicLong;

/**
 * 会话。会话持有当前有效凭证 id；会话撤销是“根撤销”，
 * 其名下所有凭证（含已轮换的旧凭证）一并失效。
 *
 * <p>会话另维护 {@code lastActiveAt}（最近活跃时间）：登录时等于签发时间，
 * 刷新成功与访问放行都会顺延它；空闲超时判定以它为基准。</p>
 *
 * <p><b>并发契约：</b>{@link #rotate} 与 {@link #markRevoked} 只能在
 * {@code SessionStore} 的会话级锁内调用；读取（含 currentCredentialId、
 * revoked 等 volatile 字段）可以在锁外进行。{@link #touch} 是单调递增的
 * 原子写，允许在锁外并发调用。</p>
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
    private volatile TerminationCause terminationCause;
    private final AtomicLong lastActiveAt;

    public SessionInfo(String id, String userId, String username, long createdAt, long ttlMillis,
                       String currentCredentialId, long currentVersion) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
        this.currentCredentialId = currentCredentialId;
        this.currentVersion = currentVersion;
        this.lastActiveAt = new AtomicLong(createdAt);
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
    /** 终止原因；会话未被终止时返回 null。 */
    public TerminationCause getTerminationCause() { return terminationCause; }
    public long getLastActiveAt() { return lastActiveAt.get(); }

    /**
     * 记录一次活动（登录、刷新成功、访问放行）。单调递增、可并发调用：
     * 时钟回拨或并发乱序都不会让最近活跃时间倒退。
     */
    public void touch(long now) {
        lastActiveAt.accumulateAndGet(now, Math::max);
    }

    /**
     * 空闲判定：{@code now >= lastActiveAt + idleTimeoutMillis} 即视为空闲超时
     * （边界含等于，与绝对过期边界风格一致）。idleTimeoutMillis &lt;= 0 表示关闭空闲判定。
     */
    public boolean isIdleAt(long now, long idleTimeoutMillis) {
        if (idleTimeoutMillis <= 0) {
            return false;
        }
        return now >= lastActiveAt.get() + idleTimeoutMillis;
    }

    /**
     * 把会话当前指针从旧凭证原子地切换到新凭证。必须在会话级锁内调用。
     */
    public void rotate(String newCredentialId, long newVersion) {
        this.currentCredentialId = newCredentialId;
        this.currentVersion = newVersion;
    }

    /**
     * 标记会话被撤销（主动撤销）。必须在会话级锁内调用；重复撤销保留首次原因。
     */
    public void markRevoked(long at, String reason) {
        markTerminated(at, reason, TerminationCause.USER_REVOKED);
    }

    /**
     * 标记会话被终止。必须在会话级锁内调用；重复终止保留首次原因与原因类别
     * （不互相覆盖），已终止会话不存在任何“重新激活”路径。
     */
    public void markTerminated(long at, String reason, TerminationCause cause) {
        if (!this.revoked) {
            this.revoked = true;
            this.revokedAt = at;
            this.revokeReason = reason;
            this.terminationCause = cause;
        }
    }
}
