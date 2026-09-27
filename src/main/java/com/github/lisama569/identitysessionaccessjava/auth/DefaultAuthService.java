package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.audit.AuditService;
import com.github.lisama569.identitysessionaccessjava.model.AuditEventType;
import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.CredentialState;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.model.RevokeKind;
import com.github.lisama569.identitysessionaccessjava.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.model.SessionView;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;
import com.github.lisama569.identitysessionaccessjava.store.SessionStore;
import com.github.lisama569.identitysessionaccessjava.store.UserStore;
import com.github.lisama569.identitysessionaccessjava.time.TimeSource;
import com.github.lisama569.identitysessionaccessjava.token.TokenPayload;
import com.github.lisama569.identitysessionaccessjava.token.TokenService;
import com.github.lisama569.identitysessionaccessjava.web.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 认证服务默认实现。
 *
 * <p>关键时序保证：</p>
 * <ul>
 *   <li>刷新轮换由 {@code SessionStore.atomicRefresh} 在会话级锁内一次提交，
 *       旧凭证在事务提交之时立即 ROTATED，同一会话并发刷新恰有一个赢家；</li>
 *   <li>竞争失败（NOT_CURRENT 且旧凭证刚被本次并发刷新轮换）报
 *       CONCURRENT_REFRESH_CONFLICT；事后重放旧凭证报 CREDENTIAL_ROTATED，二者可区分；</li>
 *   <li>撤销优先于一切：先查会话/凭证撤销位，再判过期与轮换，因此“过期 + 已撤销”
 *       稳定归为撤销类原因；撤销在锁内完成并立即对后续判定可见，不存在静默复活。</li>
 * </ul>
 */
@Service
public class DefaultAuthService implements AuthService {

    /** 账号级活跃会话上限默认值。 */
    public static final int DEFAULT_MAX_ACTIVE_SESSIONS = 5;
    /** 会话空闲超时默认值（30 分钟）。 */
    public static final long DEFAULT_IDLE_TIMEOUT_MILLIS = 1_800_000L;

    private final UserStore userStore;
    private final SessionStore sessionStore;
    private final TokenService tokenService;
    private final PasswordHasher passwordHasher;
    private final AuditService audit;
    private final TimeSource timeSource;
    private final long ttlMillis;
    private final int maxActiveSessions;
    private final long idleTimeoutMillis;

    @Autowired
    public DefaultAuthService(UserStore userStore, SessionStore sessionStore, TokenService tokenService,
                              PasswordHasher passwordHasher, AuditService audit, TimeSource timeSource,
                              @Value("${identity.session.ttl-millis:900000}") long ttlMillis,
                              @Value("${identity.session.max-active-sessions-per-account:5}") int maxActiveSessions,
                              @Value("${identity.session.idle-timeout-millis:1800000}") long idleTimeoutMillis) {
        this.userStore = userStore;
        this.sessionStore = sessionStore;
        this.tokenService = tokenService;
        this.passwordHasher = passwordHasher;
        this.audit = audit;
        this.timeSource = timeSource;
        this.ttlMillis = ttlMillis;
        this.maxActiveSessions = maxActiveSessions;
        this.idleTimeoutMillis = idleTimeoutMillis;
    }

    /** 兼容构造：使用默认容量上限与默认空闲超时。 */
    public DefaultAuthService(UserStore userStore, SessionStore sessionStore, TokenService tokenService,
                              PasswordHasher passwordHasher, AuditService audit, TimeSource timeSource,
                              long ttlMillis) {
        this(userStore, sessionStore, tokenService, passwordHasher, audit, timeSource, ttlMillis,
                DEFAULT_MAX_ACTIVE_SESSIONS, DEFAULT_IDLE_TIMEOUT_MILLIS);
    }

    /**
     * 显式并发批次：测试或高并发调用方可先 joinRefreshBatch 登记，再并发 refresh。
     * 普通单请求路径（未设置该 ThreadLocal）会自动入批/离批，行为保持简单。
     */
    private static final ThreadLocal<RefreshBatch> CURRENT_BATCH = new ThreadLocal<>();

    private record RefreshBatch(String sessionId, String requestId) {
    }

    @Override
    public Object joinRefreshBatch(String presentedToken) {
        TokenPayload payload = tokenService.parse(presentedToken);
        if (payload == null) {
            throw new AuthenticationException(DenyReason.CREDENTIAL_NOT_FOUND, "凭证缺失或无效");
        }
        CredentialRecord credential = sessionStore.findCredential(payload.credentialId())
                .orElseThrow(() -> new AuthenticationException(DenyReason.CREDENTIAL_NOT_FOUND,
                        "凭证不存在", payload.credentialId()));
        RefreshBatch batch = new RefreshBatch(credential.getSessionId(), newId());
        sessionStore.beginRefreshAttempt(batch.sessionId(), batch.requestId());
        CURRENT_BATCH.set(batch);
        return batch;
    }

    @Override
    public void leaveRefreshBatch(Object batchHandle) {
        try {
            if (batchHandle instanceof RefreshBatch batch) {
                sessionStore.endRefreshAttempt(batch.sessionId(), batch.requestId());
            }
        } finally {
            CURRENT_BATCH.remove();
        }
    }

    @Override
    public TokenResponse login(String username, String rawPassword) {
        long now = timeSource.nowMillis();
        UserAccount account = userStore.findByUsername(username).orElse(null);
        if (account == null || !passwordHasher.matches(rawPassword, account.getPasswordSalt(),
                account.getPasswordHash())) {
            audit.record(AuditEventType.LOGIN_FAILURE, username, null, null, null, null,
                    DenyReason.BAD_CREDENTIALS, "用户名或口令错误");
            throw new AuthenticationException(DenyReason.BAD_CREDENTIALS, "用户名或口令错误");
        }
        if (!account.isEnabled()) {
            audit.record(AuditEventType.LOGIN_FAILURE, username, null, null, null, null,
                    DenyReason.USER_DISABLED, "账户已停用");
            throw new AuthenticationException(DenyReason.USER_DISABLED, "账户已停用");
        }

        String sessionId = newId();
        String credentialId = newId();
        long version = 1L;
        String token = tokenService.issueToken(credentialId, sessionId, account.getId(), version);
        CredentialRecord credential = new CredentialRecord(credentialId, sessionId, account.getId(),
                account.getUsername(), token, now, now + ttlMillis, version, CredentialState.ACTIVE);
        SessionInfo session = new SessionInfo(sessionId, account.getId(), account.getUsername(),
                now, ttlMillis, credentialId, version);
        // 建会话与容量淘汰在账号级锁内一次完成：并发登录收敛后活跃会话数不超上限
        List<SessionInfo> evicted = sessionStore.atomicCreateSession(session, credential,
                maxActiveSessions, now);
        for (SessionInfo victim : evicted) {
            for (CredentialRecord c : sessionStore.credentialsOfSession(victim.getId())) {
                audit.record(AuditEventType.CREDENTIAL_REVOKED, victim.getUsername(),
                        victim.getId(), c.getId(), null, null, null,
                        "容量淘汰连带凭证失效（账号活跃会话上限=" + maxActiveSessions + "）");
            }
            audit.record(AuditEventType.SESSION_REVOKED, victim.getUsername(), victim.getId(),
                    null, null, null, null,
                    "容量淘汰：账号 " + account.getUsername() + " 活跃会话超上限 "
                            + maxActiveSessions + "，最久未活跃会话被结束（lastActiveAt="
                            + victim.getLastActiveAt() + "），后续使用其凭证将拒绝 "
                            + DenyReason.SESSION_CAPACITY_EVICTED);
        }

        audit.record(AuditEventType.LOGIN_SUCCESS, account.getUsername(), sessionId, credentialId,
                null, null, null, "登录成功，签发凭证 v" + version
                        + (evicted.isEmpty() ? "" : "；本次登录触发容量淘汰 " + evicted.size() + " 个会话"));
        return toResponse(credential, sessionId);
    }

    @Override
    public TokenResponse refresh(String presentedToken) {
        long now = timeSource.nowMillis();
        TokenPayload payload = tokenService.parse(presentedToken);
        if (payload == null) {
            audit.record(AuditEventType.REFRESH_FAILURE, null, null, null, null, null,
                    DenyReason.CREDENTIAL_NOT_FOUND, "凭证缺失或签名无效");
            throw new AuthenticationException(DenyReason.CREDENTIAL_NOT_FOUND, "凭证缺失或无效");
        }
        String presentedId = payload.credentialId();
        CredentialRecord presented = sessionStore.findCredential(presentedId).orElse(null);
        if (presented == null) {
            audit.record(AuditEventType.REFRESH_FAILURE, null, payload.sessionId(), presentedId,
                    null, null, DenyReason.CREDENTIAL_NOT_FOUND, "凭证标识不存在");
            throw new AuthenticationException(DenyReason.CREDENTIAL_NOT_FOUND, "凭证不存在",
                    presentedId);
        }
        SessionInfo session = sessionStore.findSession(presented.getSessionId()).orElse(null);
        if (session == null) {
            audit.record(AuditEventType.REFRESH_FAILURE, presented.getUsername(),
                    presented.getSessionId(), presentedId, null, null,
                    DenyReason.SESSION_NOT_FOUND, "会话不存在");
            throw new AuthenticationException(DenyReason.SESSION_NOT_FOUND, "会话不存在",
                    presentedId);
        }

        // 锁外不做任何状态分类：撤销/过期/轮换/并发冲突全部由会话锁内的
        // 原子操作给出权威结论，避免“锁外读到旧状态”造成的误分类。
        long newVersion = presented.getVersion() + 1;
        String newCredentialId = newId();
        String newToken = tokenService.issueToken(newCredentialId, session.getId(),
                presented.getUserId(), newVersion);
        CredentialRecord newCredential = new CredentialRecord(newCredentialId, session.getId(),
                presented.getUserId(), presented.getUsername(), newToken, now, now + ttlMillis,
                newVersion, CredentialState.ACTIVE);

        RefreshBatch batch = CURRENT_BATCH.get();
        boolean autoBatch = batch == null;
        if (autoBatch) {
            batch = new RefreshBatch(session.getId(), newId());
            sessionStore.beginRefreshAttempt(batch.sessionId(), batch.requestId());
            CURRENT_BATCH.set(batch);
        }
        SessionStore.RefreshOutcome outcome;
        try {
            outcome = sessionStore.atomicRefresh(batch.sessionId(), batch.requestId(),
                    presentedId, newCredential, now, idleTimeoutMillis);
        } finally {
            if (autoBatch) {
                sessionStore.endRefreshAttempt(batch.sessionId(), batch.requestId());
                CURRENT_BATCH.remove();
            }
        }
        return switch (outcome.kind()) {
            case SUCCESS -> {
                audit.record(AuditEventType.REFRESH_SUCCESS, session.getUsername(),
                        session.getId(), newCredentialId, null, null, null,
                        "轮换成功：旧凭证 " + presentedId + " 在事务提交时立即 ROTATED，"
                                + "新凭证 v" + newVersion);
                yield toResponse(newCredential, session.getId());
            }
            case REVOKED -> {
                SessionInfo current = sessionStore.findSession(session.getId()).orElse(null);
                boolean sessionRevoked = current != null && current.isRevoked();
                DenyReason reason;
                if (sessionRevoked && current.getRevokeKind() == RevokeKind.CAPACITY) {
                    reason = DenyReason.SESSION_CAPACITY_EVICTED;
                } else {
                    reason = sessionRevoked ? DenyReason.SESSION_REVOKED
                            : DenyReason.CREDENTIAL_REVOKED;
                }
                audit.record(AuditEventType.REFRESH_FAILURE, session.getUsername(),
                        session.getId(), presentedId, null, null, reason,
                        "锁内权威判定：已撤销（会话撤销位=" + sessionRevoked
                                + (sessionRevoked ? "，类别=" + current.getRevokeKind() : "")
                                + "），禁止刷新");
                throw new AuthenticationException(reason, "凭证已撤销，禁止刷新", presentedId);
            }
            case IDLE_EXPIRED -> {
                audit.record(AuditEventType.REFRESH_FAILURE, session.getUsername(),
                        session.getId(), presentedId, null, null, DenyReason.SESSION_IDLE_EXPIRED,
                        "锁内权威判定：会话空闲超时，lastActiveAt=" + session.getLastActiveAt()
                                + "，空闲上限=" + idleTimeoutMillis + "ms，当前 " + now
                                + "（与绝对过期相区分）");
                throw new AuthenticationException(DenyReason.SESSION_IDLE_EXPIRED,
                        "会话空闲超时，请重新登录", presentedId);
            }
            case EXPIRED -> {
                audit.record(AuditEventType.REFRESH_FAILURE, session.getUsername(),
                        session.getId(), presentedId, null, null, DenyReason.CREDENTIAL_EXPIRED,
                        "锁内权威判定：凭证已于 " + presented.getExpiresAt()
                                + " 过期，当前 " + now + "（边界 now>=expiresAt）");
                throw new AuthenticationException(DenyReason.CREDENTIAL_EXPIRED, "凭证已过期",
                        presentedId);
            }
            case CONCURRENT_LOSS -> {
                audit.record(AuditEventType.REFRESH_FAILURE, session.getUsername(),
                        session.getId(), presentedId, null, null,
                        DenyReason.CONCURRENT_REFRESH_CONFLICT,
                        "锁内权威判定：并发刷新竞争失败，获胜凭证="
                                + outcome.currentCredentialId()
                                + "；失败凭证已在同一事务中收敛为 ROTATED");
                throw new AuthenticationException(DenyReason.CONCURRENT_REFRESH_CONFLICT,
                        "并发刷新竞争失败：同一会话仅允许一个有效凭证", presentedId);
            }
            case SUPERSEDED_REPLAY -> {
                audit.record(AuditEventType.REFRESH_FAILURE, session.getUsername(),
                        session.getId(), presentedId, null, null, DenyReason.CREDENTIAL_ROTATED,
                        "锁内权威判定：旧凭证事后重放，当前凭证="
                                + outcome.currentCredentialId());
                throw new AuthenticationException(DenyReason.CREDENTIAL_ROTATED,
                        "凭证已被轮换，旧凭证立即失效", presentedId);
            }
            case SESSION_NOT_FOUND -> throw new AuthenticationException(DenyReason.SESSION_NOT_FOUND,
                    "会话不存在", presentedId);
            case PRESENTED_NOT_FOUND -> throw new AuthenticationException(
                    DenyReason.CREDENTIAL_NOT_FOUND, "凭证不存在", presentedId);
        };
    }

    @Override
    public void revokeSession(String sessionId, String reason) {
        long now = timeSource.nowMillis();
        List<CredentialRecord> changed = sessionStore.atomicRevokeSession(sessionId, reason, now);
        if (changed == null) {
            audit.record(AuditEventType.SESSION_REVOKED, null, sessionId, null, null, null,
                    DenyReason.SESSION_NOT_FOUND, "撤销失败：会话不存在");
            throw new AuthenticationException(DenyReason.SESSION_NOT_FOUND, "会话不存在");
        }
        SessionInfo session = sessionStore.findSession(sessionId).orElse(null);
        String subject = session == null ? null : session.getUsername();
        changed.forEach(c -> audit.record(AuditEventType.CREDENTIAL_REVOKED, subject, sessionId,
                c.getId(), null, null, null, "会话撤销连带凭证失效: " + reason));
        audit.record(AuditEventType.SESSION_REVOKED, subject, sessionId, null, null, null, null,
                "会话已撤销，生效时刻 " + now + "（后续访问立即拒绝）: " + reason);
    }

    @Override
    public void revokeCredential(String credentialId, String reason) {
        long now = timeSource.nowMillis();
        CredentialRecord c = sessionStore.findCredential(credentialId).orElse(null);
        if (c == null) {
            audit.record(AuditEventType.CREDENTIAL_REVOKED, null, null, credentialId, null, null,
                    DenyReason.CREDENTIAL_NOT_FOUND, "撤销失败：凭证不存在");
            throw new AuthenticationException(DenyReason.CREDENTIAL_NOT_FOUND, "凭证不存在",
                    credentialId);
        }
        boolean changed = sessionStore.atomicRevokeCredential(credentialId, reason, now);
        audit.record(AuditEventType.CREDENTIAL_REVOKED, c.getUsername(), c.getSessionId(),
                credentialId, null, null, null,
                "凭证撤销: " + reason + (changed ? "（状态迁移 -> REVOKED，后续访问立即拒绝）"
                        : "（此前已撤销，首次撤销原因保留，无状态覆盖）"));
    }

    @Override
    public List<SessionView> listActiveSessions(String username) {
        long now = timeSource.nowMillis();
        UserAccount account = userStore.findByUsername(username).orElse(null);
        if (account == null) {
            audit.record(AuditEventType.ACCESS_DENIED, username, null, null, null, null,
                    DenyReason.BAD_CREDENTIALS, "会话治理查询失败：账号不存在");
            throw new AuthenticationException(DenyReason.BAD_CREDENTIALS, "账号不存在");
        }
        List<SessionView> views = new ArrayList<>();
        for (SessionInfo s : sessionStore.sessionsOfAccount(account.getId())) {
            // 活跃 = 未撤销 且 当前凭证未绝对过期 且 未空闲超时；已结束/已失效会话不出现
            if (s.isRevoked() || s.isIdleExpiredAt(now, idleTimeoutMillis)) {
                continue;
            }
            CredentialRecord current = sessionStore.findCredential(s.getCurrentCredentialId())
                    .orElse(null);
            if (current == null || current.isExpiredAt(now)) {
                continue;
            }
            views.add(new SessionView(s.getId(), s.getUserId(), s.getUsername(), s.getCreatedAt(),
                    s.getLastActiveAt(), s.getCurrentVersion(), s.getCurrentCredentialId(),
                    current.getExpiresAt()));
        }
        views.sort(java.util.Comparator.comparingLong(SessionView::issuedAt));
        audit.record(AuditEventType.ACCESS_ALLOWED, username, null, null, null, null, null,
                "会话治理查询：账号活跃会话数=" + views.size());
        return List.copyOf(views);
    }

    @Override
    public SessionInfo requireSession(String sessionId) {
        return sessionStore.findSession(sessionId)
                .orElseThrow(() -> new AuthenticationException(DenyReason.SESSION_NOT_FOUND,
                        "会话不存在"));
    }

    @Override
    public CredentialRecord requireCredential(String credentialId) {
        return sessionStore.findCredential(credentialId)
                .orElseThrow(() -> new AuthenticationException(DenyReason.CREDENTIAL_NOT_FOUND,
                        "凭证不存在", credentialId));
    }

    private static String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private TokenResponse toResponse(CredentialRecord c, String sessionId) {
        return new TokenResponse(c.getToken(), sessionId, c.getId(), c.getVersion(),
                c.getIssuedAt(), c.getExpiresAt(), ttlMillis / 1000);
    }
}
