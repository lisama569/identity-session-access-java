package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.time.Instant;

/** 只追加的审计记录。 */
public record AuditEvent(long sequence, Instant at, AuditAction action,
                         String userId, String sessionId, String tokenId,
                         DenyReason reason, String detail) {
}
