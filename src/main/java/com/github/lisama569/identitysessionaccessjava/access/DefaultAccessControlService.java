package com.github.lisama569.identitysessionaccessjava.access;

import com.github.lisama569.identitysessionaccessjava.audit.AuditService;
import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;
import com.github.lisama569.identitysessionaccessjava.model.AuditEventType;
import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.CredentialState;
import com.github.lisama569.identitysessionaccessjava.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;
import com.github.lisama569.identitysessionaccessjava.store.SessionStore;
import com.github.lisama569.identitysessionaccessjava.store.UserStore;
import com.github.lisama569.identitysessionaccessjava.time.TimeSource;
import com.github.lisama569.identitysessionaccessjava.token.TokenPayload;
import com.github.lisama569.identitysessionaccessjava.token.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 统一访问判定。
 *
 * <p>判定顺序即拒绝原因的优先级（从高到低）：</p>
 * <ol>
 *   <li>未携带/非法凭证 —— {@code UNAUTHENTICATED}</li>
 *   <li>凭证无法识别 —— {@code CREDENTIAL_NOT_FOUND}</li>
 *   <li>会话不存在 —— {@code SESSION_NOT_FOUND}</li>
 *   <li>会话撤销 / 凭证撤销（撤销优先于一切，含过期与轮换）</li>
 *   <li>凭证过期 —— {@code CREDENTIAL_EXPIRED}（边界：now &gt;= expiresAt）</li>
 *   <li>凭证已轮换 —— {@code CREDENTIAL_ROTATED}</li>
 *   <li>非会话当前凭证 —— {@code CONCURRENT_REFRESH_CONFLICT}</li>
 *   <li>账户停用 —— {@code USER_DISABLED}</li>
 *   <li>权限不足 —— {@code PERMISSION_DENIED}（默认拒绝，无策略显式允许即拒绝）</li>
 * </ol>
 *
 * <p>所有状态每次实时读取存储中的权威记录，不缓存身份与判定结果，
 * 因此撤销、降权对下一次判定立即生效。</p>
 */
@Service
public class DefaultAccessControlService implements AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(DefaultAccessControlService.class);

    private final TokenService tokenService;
    private final SessionStore sessionStore;
    private final UserStore userStore;
    private final PolicyRegistry policyRegistry;
    private final AuditService audit;
    private final TimeSource timeSource;

    public DefaultAccessControlService(TokenService tokenService, SessionStore sessionStore,
                                       UserStore userStore, PolicyRegistry policyRegistry,
                                       AuditService audit, TimeSource timeSource) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
        this.userStore = userStore;
        this.policyRegistry = policyRegistry;
        this.audit = audit;
        this.timeSource = timeSource;
    }

    @Override
    public AuthDecision decide(String presentedToken, String permission, String resource) {
        long now = timeSource.nowMillis();

        if (presentedToken == null || presentedToken.isBlank()) {
            return deny(DenyReason.UNAUTHENTICATED, "未携带会话凭证", permission, resource,
                    null, null, null, null);
        }
        TokenPayload payload = tokenService.parse(presentedToken);
        if (payload == null) {
            return deny(DenyReason.UNAUTHENTICATED, "凭证格式非法或签名无效", permission, resource,
                    null, null, null, null);
        }
        CredentialRecord credential = sessionStore.findCredential(payload.credentialId()).orElse(null);
        if (credential == null) {
            return deny(DenyReason.CREDENTIAL_NOT_FOUND, "凭证标识不存在（可能从未签发或已清除）",
                    permission, resource, null, null, payload.sessionId(), payload.credentialId());
        }
        String cid = credential.getId();
        String sid = credential.getSessionId();
        SessionInfo session = sessionStore.findSession(sid).orElse(null);
        if (session == null) {
            return deny(DenyReason.SESSION_NOT_FOUND, "凭证所属会话不存在", permission, resource,
                    credential.getUserId(), credential.getUsername(), sid, cid);
        }
        // 撤销优先：保证“已撤销/降权身份绝不因过期判定或缓存而放行”
        if (session.isRevoked()) {
            return deny(DenyReason.SESSION_REVOKED,
                    "会话已于 " + session.getRevokedAt() + " 被撤销（原因: "
                            + session.getRevokeReason() + "），名下凭证全部失效",
                    permission, resource, credential.getUserId(), credential.getUsername(), sid, cid);
        }
        if (credential.getState() == CredentialState.REVOKED) {
            return deny(DenyReason.CREDENTIAL_REVOKED, "凭证本身已被撤销", permission, resource,
                    credential.getUserId(), credential.getUsername(), sid, cid);
        }
        if (credential.isExpiredAt(now)) {
            return deny(DenyReason.CREDENTIAL_EXPIRED,
                    "凭证已于 " + credential.getExpiresAt() + " 过期（当前 " + now + "，边界 now>=expiresAt）",
                    permission, resource, credential.getUserId(), credential.getUsername(), sid, cid);
        }
        if (credential.getState() == CredentialState.ROTATED) {
            return deny(DenyReason.CREDENTIAL_ROTATED,
                    "凭证已在刷新轮换时立即失效，后继凭证=" + credential.getReplacedByCredentialId(),
                    permission, resource, credential.getUserId(), credential.getUsername(), sid, cid);
        }
        if (!cid.equals(session.getCurrentCredentialId())) {
            return deny(DenyReason.CONCURRENT_REFRESH_CONFLICT,
                    "该凭证不是会话当前有效凭证（并发刷新中未胜出），当前凭证="
                            + session.getCurrentCredentialId(),
                    permission, resource, credential.getUserId(), credential.getUsername(), sid, cid);
        }
        UserAccount account = userStore.findById(credential.getUserId()).orElse(null);
        if (account == null) {
            return deny(DenyReason.USER_DISABLED, "账户不存在或已被移除", permission, resource,
                    credential.getUserId(), credential.getUsername(), sid, cid);
        }
        if (!account.isEnabled()) {
            return deny(DenyReason.USER_DISABLED, "账户已停用，其凭证不再具有访问能力",
                    permission, resource, account.getId(), account.getUsername(), sid, cid);
        }

        // 授权：角色/属性策略实时求值；默认拒绝，至少一条策略显式允许才放行。
        boolean anyExplicitAllow = false;
        for (AccessPolicy policy : policyRegistry.policiesFor(permission)) {
            Boolean verdict = policy.evaluate(account, credential, resource);
            if (Boolean.TRUE.equals(verdict)) {
                anyExplicitAllow = true;
                break;
            }
        }
        if (!anyExplicitAllow) {
            return deny(DenyReason.PERMISSION_DENIED,
                    "权限不足：主体角色 " + account.getRoles() + " 与属性 "
                            + account.getAttributes() + " 均未被任何策略显式授予 " + permission
                            + "（默认拒绝）",
                    permission, resource, account.getId(), account.getUsername(), sid, cid);
        }

        AuthDecision decision = AuthDecision.allow(permission, resource, account.getId(),
                account.getUsername(), sid, cid);
        log.info("DECIDE credential={} permission={} resource={} verdict=ALLOW basis=策略实时求值通过",
                cid, permission, resource);
        audit.record(AuditEventType.ACCESS_ALLOWED, account.getUsername(), sid, cid, permission,
                resource, null, "允许访问，策略实时求值通过");
        return decision;
    }

    @Override
    public AuthDecision requireAllowed(String presentedToken, String permission, String resource) {
        AuthDecision decision = decide(presentedToken, permission, resource);
        if (!decision.isAllowed()) {
            throw new AuthorizationException(decision);
        }
        return decision;
    }

    private AuthDecision deny(DenyReason reason, String message, String permission, String resource,
                              String userId, String username, String sessionId, String credentialId) {
        AuthDecision d = AuthDecision.deny(reason, "DENY[" + reason + "]: " + message, permission,
                resource, userId, username, sessionId, credentialId);
        log.info("DECIDE credential={} permission={} resource={} verdict=DENY basis={}",
                credentialId, permission, resource, reason);
        audit.record(AuditEventType.ACCESS_DENIED, username, sessionId, credentialId, permission,
                resource, reason, message);
        return d;
    }
}
