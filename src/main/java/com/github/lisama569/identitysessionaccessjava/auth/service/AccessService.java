package com.github.lisama569.identitysessionaccessjava.auth.service;

import com.github.lisama569.identitysessionaccessjava.auth.model.AccessDecision;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.AuditAction;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.Principal;
import com.github.lisama569.identitysessionaccessjava.auth.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenStatus;
import com.github.lisama569.identitysessionaccessjava.auth.model.User;
import com.github.lisama569.identitysessionaccessjava.auth.policy.PolicyEngine;
import com.github.lisama569.identitysessionaccessjava.auth.store.SessionStore;
import com.github.lisama569.identitysessionaccessjava.auth.store.UserStore;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;

/**
 * 访问判定入口。
 *
 * <p>关键不变量：</p>
 * <ul>
 *   <li><b>无缓存</b>：每次访问都实时读取凭证状态、会话状态与用户实时角色/属性，
 *       因此撤销即时生效、降权即时生效，不会因缓存或并发而放行。</li>
 *   <li><b>拒绝原因可区分</b>：未认证 / 过期 / 已轮换 / 并发轮换失效 /
 *       凭证撤销 / 会话撤销 / 用户停用 / 权限不足分别给出不同 {@link DenyReason}。</li>
 *   <li>会话状态变更仍以会话锁串行化，这里在锁内做“状态 + 时钟”复核，
 *       保证与并发刷新/撤销读到的结论一致。</li>
 * </ul>
 */
@Service
public class AccessService {

    private final SessionStore sessions;
    private final UserStore users;
    private final PolicyEngine policyEngine;
    private final AuditService audit;
    private final Clock clock;

    public AccessService(SessionStore sessions, UserStore users, PolicyEngine policyEngine,
                         AuditService audit, Clock clock) {
        this.sessions = sessions;
        this.users = users;
        this.policyEngine = policyEngine;
        this.audit = audit;
        this.clock = clock;
    }

    public AccessDecision authorize(String bearerSecret, AccessRequest request) {
        if (bearerSecret == null || bearerSecret.isBlank()) {
            return record(DenyReason.UNAUTHENTICATED, null, null, null,
                    "no credential presented");
        }
        String secret = bearerSecret.startsWith("Bearer ")
                ? bearerSecret.substring("Bearer ".length())
                : bearerSecret;

        TokenInfo token = sessions.tokenBySecret(secret);
        if (token == null) {
            return record(DenyReason.UNAUTHENTICATED, null, null, null,
                    "presented credential is not recognized");
        }

        SessionInfo session = sessions.getSession(token.getSessionId());
        // 与刷新/撤销共用同一把会话锁，保证判定时刻状态视图一致。
        sessions.lockFor(token.getSessionId()).lock();
        try {
            Instant now = clock.instant();

            if (session != null && session.isRevoked()) {
                return record(DenyReason.SESSION_REVOKED,
                        session.getUserId(), token.getSessionId(), token.getTokenId(),
                        "session revoked at " + session.getRevokedAt()
                                + " reason=" + session.getRevokeReason());
            }

            // 过期边界：expiresAt 时刻（!isAfter(now)）即为过期，确定且可测试。
            TokenStatus effectiveStatus = token.getStatus();
            if (effectiveStatus == TokenStatus.ACTIVE && !token.getExpiresAt().isAfter(now)) {
                effectiveStatus = TokenStatus.EXPIRED;
                token.setStatus(TokenStatus.EXPIRED);
            }

            switch (effectiveStatus) {
                case ACTIVE -> {
                    if (session == null
                            || !token.getTokenId().equals(session.getCurrentTokenId())
                            || token.getSerial() != session.getCurrentSerial()) {
                        // 当前仍 ACTIVE 却不是会话指针所指凭证：被并发刷新抢先。
                        return record(DenyReason.CONCURRENTLY_ROTATED,
                                session == null ? null : session.getUserId(),
                                token.getSessionId(), token.getTokenId(),
                                "credential is stale due to concurrent refresh");
                    }
                }
                case ROTATED -> {
                    DenyReason reason = DenyReason.TOKEN_ROTATED;
                    return record(reason,
                            session == null ? null : session.getUserId(),
                            token.getSessionId(), token.getTokenId(),
                            "credential was rotated at " + token.getRotatedAt()
                                    + ", superseded by " + token.getSupersededBy());
                }
                case EXPIRED -> {
                    return record(DenyReason.TOKEN_EXPIRED,
                            session == null ? null : session.getUserId(),
                            token.getSessionId(), token.getTokenId(),
                            "credential expired at " + token.getExpiresAt()
                                    + ", now=" + now);
                }
                case REVOKED -> {
                    return record(DenyReason.TOKEN_REVOKED,
                            session == null ? null : session.getUserId(),
                            token.getSessionId(), token.getTokenId(),
                            "credential has been revoked");
                }
            }

            // 实时构造身份快照：角色/属性来自用户对象当前值，不做任何缓存。
            User user = users.findById(session.getUserId());
            if (user == null || !user.isEnabled()) {
                return record(DenyReason.USER_DISABLED, user == null ? null : user.getId(),
                        session.getSessionId(), token.getTokenId(),
                        "user is disabled or no longer exists");
            }

            Principal principal = new Principal(
                    user.getId(),
                    user.getUsername(),
                    Set.copyOf(user.getRoles()),
                    Map_copyOf(user.getAttributes()),
                    session.getSessionId(),
                    token.getTokenId());

            AccessDecision decision = policyEngine.decide(principal, request);
            if (decision.allowed()) {
                audit.emit(AuditAction.ACCESS_GRANTED, user.getId(),
                        session.getSessionId(), token.getTokenId(), null,
                        "resource=" + request.resource() + " action=" + request.action()
                                + " basis=" + decision.basis());
            } else {
                audit.emit(AuditAction.ACCESS_DENIED, user.getId(),
                        session.getSessionId(), token.getTokenId(), decision.reason(),
                        "resource=" + request.resource() + " action=" + request.action()
                                + " basis=" + decision.basis());
            }
            return decision;
        } finally {
            sessions.lockFor(token.getSessionId()).unlock();
        }
    }

    private AccessDecision record(DenyReason reason, String userId, String sessionId,
                                  String tokenId, String basis) {
        AccessDecision decision = AccessDecision.deny(reason,
                new Principal(userId, null, Set.of(), java.util.Map.of(), sessionId, tokenId),
                basis);
        audit.emit(AuditAction.ACCESS_DENIED, userId, sessionId, tokenId, reason, basis);
        return decision;
    }

    private static java.util.Map<String, String> Map_copyOf(java.util.Map<String, String> source) {
        return source == null ? java.util.Map.of() : java.util.Map.copyOf(source);
    }
}
