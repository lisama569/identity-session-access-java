package com.github.lisama569.identitysessionaccessjava.audit;

import com.github.lisama569.identitysessionaccessjava.model.AuditEvent;
import com.github.lisama569.identitysessionaccessjava.model.AuditEventType;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;

import java.util.List;

/**
 * 审计服务：任何关键判定都必须在此留下记录。
 */
public interface AuditService {
    AuditEvent record(AuditEventType type, String subject, String sessionId, String credentialId,
                      String permission, String resource, DenyReason reason, String detail);
    List<AuditEvent> all();
    List<AuditEvent> bySubject(String subject);
    List<AuditEvent> bySession(String sessionId);
}
