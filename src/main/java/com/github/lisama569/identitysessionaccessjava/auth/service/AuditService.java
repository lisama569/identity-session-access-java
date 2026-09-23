package com.github.lisama569.identitysessionaccessjava.auth.service;

import com.github.lisama569.identitysessionaccessjava.auth.model.AuditAction;
import com.github.lisama569.identitysessionaccessjava.auth.model.AuditEvent;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.store.AuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.List;

/**
 * 审计记录服务：写入只追加存储并打印结构化日志。
 *
 * <p>每条日志都携带凭证标识 tokenId（非完整凭证值）、会话标识、用户标识与
 * 拒绝原因/判定依据，便于在测试输出中核对“哪个凭证、因什么结论、依据是什么”。</p>
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    private final AuditStore auditStore;
    private final Clock clock;

    public AuditService(AuditStore auditStore, Clock clock) {
        this.auditStore = auditStore;
        this.clock = clock;
    }

    public AuditEvent emit(AuditAction action, String userId, String sessionId,
                           String tokenId, DenyReason reason, String detail) {
        AuditEvent event = new AuditEvent(
                auditStore.nextSequence(),
                clock.instant(),
                action,
                userId,
                sessionId,
                tokenId,
                reason,
                detail);
        auditStore.append(event);
        log.info("AUDIT seq={} action={} user={} session={} tokenId={} reason={} detail={}",
                event.sequence(), event.action(), event.userId(), event.sessionId(),
                event.tokenId(),
                event.reason() == null ? "-" : event.reason(),
                event.detail() == null ? "-" : event.detail());
        return event;
    }

    public List<AuditEvent> events() {
        return auditStore.events();
    }
}
