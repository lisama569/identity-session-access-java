package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.time.Instant;

/** 登录会话：任一时刻只指向一个当前凭证（currentTokenId/currentSerial）。 */
public final class SessionInfo {

    private final String sessionId;
    private final String userId;
    private final Instant createdAt;
    private volatile String currentTokenId;
    private volatile long currentSerial;
    private volatile boolean revoked;
    private volatile Instant revokedAt;
    private volatile String revokeReason;

    public SessionInfo(String sessionId, String userId, Instant createdAt,
                       String currentTokenId, long currentSerial) {
        this.sessionId = sessionId;
        this.userId = userId;
        this.createdAt = createdAt;
        this.currentTokenId = currentTokenId;
        this.currentSerial = currentSerial;
    }

    public String getSessionId() { return sessionId; }
    public String getUserId() { return userId; }
    public Instant getCreatedAt() { return createdAt; }
    public String getCurrentTokenId() { return currentTokenId; }
    public long getCurrentSerial() { return currentSerial; }
    public boolean isRevoked() { return revoked; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevokeReason() { return revokeReason; }

    public void setCurrent(String tokenId, long serial) {
        this.currentTokenId = tokenId;
        this.currentSerial = serial;
    }

    public void setRevoked(Instant revokedAt, String reason) {
        this.revoked = true;
        this.revokedAt = revokedAt;
        this.revokeReason = reason;
    }
}
