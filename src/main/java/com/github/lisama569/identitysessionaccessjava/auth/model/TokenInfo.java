package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.time.Instant;

/** 会话凭证：会话内单调递增 serial，状态单向流转。 */
public final class TokenInfo {

    private final String tokenId;
    private final String secret;
    private final String sessionId;
    private final long serial;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile TokenStatus status = TokenStatus.ACTIVE;
    private volatile String supersededBy;
    private volatile Instant rotatedAt;

    public TokenInfo(String tokenId, String secret, String sessionId, long serial,
                     Instant issuedAt, Instant expiresAt) {
        this.tokenId = tokenId;
        this.secret = secret;
        this.sessionId = sessionId;
        this.serial = serial;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getTokenId() { return tokenId; }
    public String getSecret() { return secret; }
    public String getSessionId() { return sessionId; }
    public long getSerial() { return serial; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public TokenStatus getStatus() { return status; }
    public void setStatus(TokenStatus status) { this.status = status; }
    public String getSupersededBy() { return supersededBy; }
    public void setSupersededBy(String supersededBy) { this.supersededBy = supersededBy; }
    public Instant getRotatedAt() { return rotatedAt; }
    public void setRotatedAt(Instant rotatedAt) { this.rotatedAt = rotatedAt; }
}
