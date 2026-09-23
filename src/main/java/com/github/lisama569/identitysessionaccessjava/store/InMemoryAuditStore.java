package com.github.lisama569.identitysessionaccessjava.store;

import com.github.lisama569.identitysessionaccessjava.model.AuditEvent;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 本地追加式审计存储：事件顺序编号、只增不改，CopyOnWriteArrayList 保证
 * 并发追加下的读一致性。事件 id 在 append 时统一分配。
 */
@Repository
public class InMemoryAuditStore implements AuditStore {

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final AtomicLong sequence = new AtomicLong(0);

    @Override
    public AuditEvent append(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event 不能为空");
        }
        long id = sequence.incrementAndGet();
        AuditEvent stored = new AuditEvent(
                id, event.type(), event.timestamp(), event.subject(), event.sessionId(),
                event.credentialId(), event.permission(), event.resource(),
                event.reason(), event.detail());
        events.add(stored);
        return stored;
    }

    @Override
    public List<AuditEvent> findAll() {
        return List.copyOf(events);
    }

    @Override
    public List<AuditEvent> findBySubject(String subject) {
        return events.stream()
                .filter(e -> subject != null && subject.equals(e.subject()))
                .collect(Collectors.toUnmodifiableList());
    }

    @Override
    public List<AuditEvent> findBySession(String sessionId) {
        return events.stream()
                .filter(e -> sessionId != null && sessionId.equals(e.sessionId()))
                .collect(Collectors.toUnmodifiableList());
    }
}
