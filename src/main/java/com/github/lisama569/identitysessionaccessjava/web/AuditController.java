package com.github.lisama569.identitysessionaccessjava.web;

import com.github.lisama569.identitysessionaccessjava.audit.AuditService;
import com.github.lisama569.identitysessionaccessjava.model.AuditEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 审计链路查询入口（本地模拟，无需鉴权便于演示与测试）。 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/events")
    public List<AuditEvent> all() {
        return auditService.all();
    }

    @GetMapping("/events/session/{sessionId}")
    public List<AuditEvent> bySession(@PathVariable String sessionId) {
        return auditService.bySession(sessionId);
    }

    @GetMapping("/events/subject/{subject}")
    public List<AuditEvent> bySubject(@PathVariable String subject) {
        return auditService.bySubject(subject);
    }
}
