package com.github.lisama569.identitysessionaccessjava.store;

import com.github.lisama569.identitysessionaccessjava.model.AuditEvent;

import java.util.List;

/** 本地审计存储，顺序编号、永不覆盖。 */
public interface AuditStore {
    AuditEvent append(AuditEvent event);
    List<AuditEvent> findAll();
    List<AuditEvent> findBySubject(String subject);
    List<AuditEvent> findBySession(String sessionId);
}
