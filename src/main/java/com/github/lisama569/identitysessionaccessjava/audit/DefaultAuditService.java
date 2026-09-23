package com.github.lisama569.identitysessionaccessjava.audit;

import com.github.lisama569.identitysessionaccessjava.model.AuditEvent;
import com.github.lisama569.identitysessionaccessjava.model.AuditEventType;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.store.AuditStore;
import com.github.lisama569.identitysessionaccessjava.time.TimeSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 默认审计服务：每条事件同时落本地存储并打印日志。
 * 日志固定包含凭证标识与判定依据（允许/拒绝 + 原因），满足可追溯要求。
 */
@Service
public class DefaultAuditService implements AuditService {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuditService.class);

    private final AuditStore store;
    private final TimeSource timeSource;

    public DefaultAuditService(AuditStore store, TimeSource timeSource) {
        this.store = store;
        this.timeSource = timeSource;
    }

    @Override
    public AuditEvent record(AuditEventType type, String subject, String sessionId, String credentialId,
                             String permission, String resource, DenyReason reason, String detail) {
        AuditEvent stored = store.append(new AuditEvent(
                0L, type, timeSource.nowMillis(), nullToDash(subject), nullToDash(sessionId),
                nullToDash(credentialId), nullToDash(permission), nullToDash(resource),
                reason, detail));
        log.info("AUDIT eventId={} type={} subject={} session={} credential={} permission={} "
                        + "resource={} verdict={} reason={} detail={}",
                stored.eventId(), stored.type(), stored.subject(), stored.sessionId(),
                mask(stored.credentialId()), stored.permission(), stored.resource(),
                reason == null ? "ALLOW" : "DENY",
                reason == null ? "-" : reason.name(),
                detail == null ? "" : detail);
        return stored;
    }

    @Override
    public List<AuditEvent> all() {
        return store.findAll();
    }

    @Override
    public List<AuditEvent> bySubject(String subject) {
        return store.findBySubject(subject);
    }

    @Override
    public List<AuditEvent> bySession(String sessionId) {
        return store.findBySession(sessionId);
    }

    private static String nullToDash(String s) {
        return s == null ? "-" : s;
    }

    /** 日志中只打印凭证标识前缀，避免完整凭证出现在日志里。 */
    static String mask(String credentialId) {
        if (credentialId == null || "-".equals(credentialId)) {
            return "-";
        }
        return credentialId.length() <= 8 ? credentialId + "***"
                : credentialId.substring(0, 8) + "***";
    }
}
