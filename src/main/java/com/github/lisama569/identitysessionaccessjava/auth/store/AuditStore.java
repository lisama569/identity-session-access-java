package com.github.lisama569.identitysessionaccessjava.auth.store;

import com.github.lisama569.identitysessionaccessjava.auth.model.AuditEvent;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 只追加审计存储（内存模拟）。
 *
 * <p>事件永不原地改写，序列号单调递增，因此审计链路的顺序可追溯、可重放。
 * 读操作返回快照副本，避免遍历期间被追加动作干扰。</p>
 */
@Component
public class AuditStore {

    private final List<AuditEvent> events = java.util.Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong sequence = new AtomicLong(0);

    /** 分配下一个单调递增序号（真正落库在 {@link #append} 中完成）。 */
    public long nextSequence() {
        return sequence.incrementAndGet();
    }

    public AuditEvent append(AuditEvent event) {
        events.add(event);
        return event;
    }

    public List<AuditEvent> events() {
        synchronized (events) {
            return List.copyOf(events);
        }
    }

    public void clear() {
        events.clear();
    }
}
