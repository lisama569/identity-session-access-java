package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 会话凭证记录。一个会话在任一时刻最多只有一张 ACTIVE 凭证；
 * 刷新成功后旧凭证立即转为 ROTATED，其失效时机为“刷新事务提交之时”。
 */
public final class CredentialRecord {
    private final String id;
    private final String sessionId;
    private final String userId;
    private final String username;
    private final String token;
    private final long issuedAt;
    private final long expiresAt;
    private final long version;
    private volatile CredentialState state;
    private volatile String replacedByCredentialId;

    public CredentialRecord(String id, String sessionId, String userId, String username, String token,
                            long issuedAt, long expiresAt, long version, CredentialState state) {
        this.id = id;
        this.sessionId = sessionId;
        this.userId = userId;
        this.username = username;
        this.token = token;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.version = version;
        this.state = state;
    }

    public String getId() { return id; }
    public String getSessionId() { return sessionId; }
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getToken() { return token; }
    public long getIssuedAt() { return issuedAt; }
    public long getExpiresAt() { return expiresAt; }
    public long getVersion() { return version; }
    public CredentialState getState() { return state; }
    public void setState(CredentialState state) { this.state = state; }
    public String getReplacedByCredentialId() { return replacedByCredentialId; }
    public void setReplacedByCredentialId(String replacedByCredentialId) {
        this.replacedByCredentialId = replacedByCredentialId;
    }

    /** 以“过期时刻”为边界：now &gt;= expiresAt 即视为过期（含边界）。 */
    public boolean isExpiredAt(long now) { return now >= expiresAt; }
}
