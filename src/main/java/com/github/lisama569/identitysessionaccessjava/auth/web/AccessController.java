package com.github.lisama569.identitysessionaccessjava.auth.web;

import com.github.lisama569.identitysessionaccessjava.auth.model.AccessDecision;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.AuditEvent;
import com.github.lisama569.identitysessionaccessjava.auth.service.AccessService;
import com.github.lisama569.identitysessionaccessjava.auth.service.AuditService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.github.lisama569.identitysessionaccessjava.auth.web.ApiModels.*;

/**
 * 访问判定与审计查询入口。
 *
 * <p>判定始终返回 200 + 结构化结论（allowed/reason/basis/tokenId），
 * 从而在一个入口下完整暴露可区分的拒绝原因；认证入口（登录/刷新）则使用
 * HTTP 状态码区分。审计接口返回只追加的全量事件链路。</p>
 */
@RestController
@RequestMapping("/api")
public class AccessController {

    private final AccessService accessService;
    private final AuditService auditService;

    public AccessController(AccessService accessService, AuditService auditService) {
        this.accessService = accessService;
        this.auditService = auditService;
    }

    @PostMapping("/access/check")
    public DecisionView check(@RequestHeader(name = "Authorization", required = false) String authorization,
                              @RequestBody AccessRequestJson request) {
        AccessDecision decision = accessService.authorize(authorization,
                new AccessRequest(request.resource(), request.action(),
                        request.resourceAttributes() == null
                                ? java.util.Map.of()
                                : request.resourceAttributes()));
        return new DecisionView(
                decision.allowed(),
                decision.reason() == null ? null : decision.reason().name(),
                decision.basis(),
                decision.tokenId());
    }

    @GetMapping("/audit")
    public List<AuditEventView> audit() {
        return auditService.events().stream()
                .map(AccessController::toView)
                .toList();
    }

    private static AuditEventView toView(AuditEvent e) {
        return new AuditEventView(e.sequence(), e.at(), e.action().name(),
                e.userId(), e.sessionId(), e.tokenId(),
                e.reason() == null ? null : e.reason().name(), e.detail());
    }
}
