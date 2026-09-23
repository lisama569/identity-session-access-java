package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 不可变审计事件，记录登录、刷新、访问与撤销链路上的每一次关键判定。
 */
public record AuditEvent(
        long eventId,
        AuditEventType type,
        long timestamp,
        String subject,
        String sessionId,
        String credentialId,
        String permission,
        String resource,
        DenyReason reason,
        String detail
) {
}
